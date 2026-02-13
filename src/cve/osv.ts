import type { CveSource } from './source.interface.js';
import type { Dependency, Vulnerability, VulnerabilitySource, Severity } from '../core/types.js';

const OSV_API_BASE = 'https://api.osv.dev/v1';
const BATCH_SIZE = 1000; // OSV querybatch supports up to 1000

/**
 * OSV.dev (Google Open Source Vulnerabilities) CVE source.
 *
 * Primary CVE source for Verimu because:
 * - Supports direct package name + ecosystem + version queries
 * - Has batch query endpoint for efficiency
 * - No authentication required
 * - Covers npm, PyPI, Go, Rust, Maven, NuGet, etc.
 * - Aggregates data from GitHub Advisory, NVD, and others
 *
 * API docs: https://google.github.io/osv.dev/api/
 */
export class OsvSource implements CveSource {
  readonly sourceId: VulnerabilitySource = 'osv';
  readonly name = 'OSV.dev (Google Open Source Vulnerabilities)';

  private fetchFn: typeof fetch;

  constructor(fetchImpl?: typeof fetch) {
    // Allow injecting fetch for testing
    this.fetchFn = fetchImpl ?? globalThis.fetch;
  }

  async checkDependencies(dependencies: Dependency[]): Promise<Vulnerability[]> {
    if (dependencies.length === 0) return [];

    const allVulns: Vulnerability[] = [];

    // Process in batches of BATCH_SIZE
    for (let i = 0; i < dependencies.length; i += BATCH_SIZE) {
      const batch = dependencies.slice(i, i + BATCH_SIZE);
      const batchVulns = await this.queryBatch(batch);
      allVulns.push(...batchVulns);
    }

    return allVulns;
  }

  /** Uses OSV's /querybatch endpoint for efficient bulk lookups */
  private async queryBatch(dependencies: Dependency[]): Promise<Vulnerability[]> {
    const queries = dependencies.map((dep) => ({
      version: dep.version,
      package: {
        name: dep.name,
        ecosystem: this.mapEcosystem(dep.ecosystem),
      },
    }));

    const response = await this.fetchFn(`${OSV_API_BASE}/querybatch`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ queries }),
    });

    if (!response.ok) {
      throw new Error(`OSV API error: ${response.status} ${response.statusText}`);
    }

    const data = (await response.json()) as OsvBatchResponse;
    const vulnerabilities: Vulnerability[] = [];

    // Each result in `results` corresponds to the query at the same index
    for (let i = 0; i < data.results.length; i++) {
      const result = data.results[i];
      const dep = dependencies[i];

      if (result.vulns && result.vulns.length > 0) {
        for (const vuln of result.vulns) {
          vulnerabilities.push(this.mapVulnerability(vuln, dep));
        }
      }
    }

    return vulnerabilities;
  }

  /** Maps an OSV vulnerability record to our Vulnerability type */
  private mapVulnerability(osvVuln: OsvVulnerability, dep: Dependency): Vulnerability {
    const cveId = this.extractCveId(osvVuln);
    const severity = this.extractSeverity(osvVuln);

    return {
      id: cveId || osvVuln.id,
      aliases: Array.from(new Set([osvVuln.id, ...(osvVuln.aliases ?? [])])),
      summary: osvVuln.summary ?? osvVuln.details?.slice(0, 200) ?? 'No description available',
      severity: severity.level,
      cvssScore: severity.score,
      packageName: dep.name,
      ecosystem: dep.ecosystem,
      affectedVersionRange: this.extractAffectedRange(osvVuln, dep.name),
      fixedVersion: this.extractFixedVersion(osvVuln, dep.name),
      exploitedInWild: false, // OSV doesn't track this — CISA KEV does
      source: 'osv',
      referenceUrl: `https://osv.dev/vulnerability/${osvVuln.id}`,
      publishedAt: osvVuln.published,
    };
  }

  /** Extracts CVE ID from aliases (prefers CVE-xxxx over GHSA-xxxx) */
  private extractCveId(vuln: OsvVulnerability): string | null {
    // Check the main ID first
    if (vuln.id.startsWith('CVE-')) return vuln.id;

    // Check aliases
    if (vuln.aliases) {
      const cve = vuln.aliases.find((a) => a.startsWith('CVE-'));
      if (cve) return cve;
    }

    return null;
  }

  /** Extracts severity from CVSS scores in the OSV record */
  private extractSeverity(vuln: OsvVulnerability): { level: Severity; score?: number } {
    // Try database_specific first (often has CVSS)
    if (vuln.severity && vuln.severity.length > 0) {
      for (const sev of vuln.severity) {
        if (sev.type === 'CVSS_V3') {
          const score = this.parseCvssScore(sev.score);
          if (score !== null) {
            return { level: this.scoreToSeverity(score), score };
          }
        }
      }
    }

    // Try to extract from database_specific
    if (vuln.database_specific?.severity) {
      const s = vuln.database_specific.severity.toUpperCase();
      if (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(s)) {
        return { level: s as Severity };
      }
    }

    return { level: 'UNKNOWN' };
  }

  /** Parses CVSS v3 vector string to extract the base score */
  private parseCvssScore(vectorOrScore: string): number | null {
    // Could be a raw score like "7.5" or a vector like "CVSS:3.1/AV:N/AC:L/..."
    const num = parseFloat(vectorOrScore);
    if (!isNaN(num) && num >= 0 && num <= 10) return num;

    // If it's a vector string, we'd need to calculate — for now return null
    // and rely on severity text
    return null;
  }

  /** Converts a CVSS score (0-10) to a severity level */
  private scoreToSeverity(score: number): Severity {
    if (score >= 9.0) return 'CRITICAL';
    if (score >= 7.0) return 'HIGH';
    if (score >= 4.0) return 'MEDIUM';
    if (score > 0.0) return 'LOW';
    return 'UNKNOWN';
  }

  /** Extracts affected version range for a specific package */
  private extractAffectedRange(vuln: OsvVulnerability, packageName: string): string | undefined {
    if (!vuln.affected) return undefined;

    for (const affected of vuln.affected) {
      if (affected.package?.name === packageName && affected.ranges) {
        for (const range of affected.ranges) {
          if (range.events) {
            const introduced = range.events.find((e) => e.introduced)?.introduced;
            const fixed = range.events.find((e) => e.fixed)?.fixed;
            if (introduced && fixed) return `>=${introduced}, <${fixed}`;
            if (introduced) return `>=${introduced}`;
          }
        }
      }
    }
    return undefined;
  }

  /** Extracts the fixed version for a specific package */
  private extractFixedVersion(vuln: OsvVulnerability, packageName: string): string | undefined {
    if (!vuln.affected) return undefined;

    for (const affected of vuln.affected) {
      if (affected.package?.name === packageName && affected.ranges) {
        for (const range of affected.ranges) {
          if (range.events) {
            const fixed = range.events.find((e) => e.fixed)?.fixed;
            if (fixed) return fixed;
          }
        }
      }
    }
    return undefined;
  }

  /** Maps our ecosystem names to OSV ecosystem names */
  private mapEcosystem(ecosystem: string): string {
    const map: Record<string, string> = {
      npm: 'npm',
      nuget: 'NuGet',
      cargo: 'crates.io',
      maven: 'Maven',
      pip: 'PyPI',
      go: 'Go',
      ruby: 'RubyGems',
      composer: 'Packagist',
    };
    return map[ecosystem] ?? ecosystem;
  }
}

// ─── OSV API Response Types ─────────────────────────────────────

interface OsvBatchResponse {
  results: Array<{
    vulns?: OsvVulnerability[];
  }>;
}

interface OsvVulnerability {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  published?: string;
  modified?: string;
  severity?: Array<{
    type: string;
    score: string;
  }>;
  affected?: Array<{
    package?: {
      name: string;
      ecosystem: string;
    };
    ranges?: Array<{
      type: string;
      events: Array<{
        introduced?: string;
        fixed?: string;
        last_affected?: string;
      }>;
    }>;
    versions?: string[];
  }>;
  database_specific?: {
    severity?: string;
    [key: string]: unknown;
  };
  references?: Array<{
    type: string;
    url: string;
  }>;
}
