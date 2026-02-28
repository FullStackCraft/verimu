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
 *
 * Note: /v1/querybatch only returns minimal data (id, modified).
 * Full vulnerability details must be fetched via /v1/vulns/{id}.
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

  /**
   * Uses OSV's /querybatch endpoint to get vulnerability IDs,
   * then fetches full details for each unique vulnerability.
   */
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

    // Collect unique vuln IDs and track which dependencies they affect
    const vulnIdToDeps = new Map<string, Dependency[]>();

    for (let i = 0; i < data.results.length; i++) {
      const result = data.results[i];
      const dep = dependencies[i];

      if (result.vulns && result.vulns.length > 0) {
        for (const vuln of result.vulns) {
          const existing = vulnIdToDeps.get(vuln.id);
          if (existing) {
            existing.push(dep);
          } else {
            vulnIdToDeps.set(vuln.id, [dep]);
          }
        }
      }
    }

    if (vulnIdToDeps.size === 0) {
      return [];
    }

    // Fetch full details for each unique vulnerability
    const vulnIds = Array.from(vulnIdToDeps.keys());
    const fullVulns = await this.fetchVulnerabilityDetails(vulnIds);

    // Map full vulnerability data to our format, linking to affected deps
    const vulnerabilities: Vulnerability[] = [];

    for (const osvVuln of fullVulns) {
      const affectedDeps = vulnIdToDeps.get(osvVuln.id) ?? [];
      for (const dep of affectedDeps) {
        vulnerabilities.push(this.mapVulnerability(osvVuln, dep));
      }
    }

    return vulnerabilities;
  }

  /**
   * Fetches full vulnerability details from /v1/vulns/{id} for each ID.
   * Makes parallel requests for efficiency.
   */
  private async fetchVulnerabilityDetails(vulnIds: string[]): Promise<OsvVulnerability[]> {
    const results: OsvVulnerability[] = [];

    // Fetch in parallel with a reasonable concurrency limit
    const CONCURRENCY = 10;
    for (let i = 0; i < vulnIds.length; i += CONCURRENCY) {
      const batch = vulnIds.slice(i, i + CONCURRENCY);
      const promises = batch.map(async (id) => {
        try {
          const response = await this.fetchFn(`${OSV_API_BASE}/vulns/${encodeURIComponent(id)}`, {
            method: 'GET',
            headers: { 'Content-Type': 'application/json' },
          });

          if (!response.ok) {
            // Log but don't fail the entire scan for individual vuln fetch errors
            console.warn(`Failed to fetch vulnerability ${id}: ${response.status}`);
            return null;
          }

          return (await response.json()) as OsvVulnerability;
        } catch (err) {
          console.warn(`Error fetching vulnerability ${id}:`, err);
          return null;
        }
      });

      const batchResults = await Promise.all(promises);
      results.push(...batchResults.filter((v): v is OsvVulnerability => v !== null));
    }

    return results;
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

  /** Parses CVSS v3 vector string to extract/calculate the base score */
  private parseCvssScore(vectorOrScore: string): number | null {
    // Could be a raw score like "7.5"
    const num = parseFloat(vectorOrScore);
    if (!isNaN(num) && num >= 0 && num <= 10) return num;

    // Parse CVSS v3.x vector string like "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    if (vectorOrScore.startsWith('CVSS:3')) {
      return this.calculateCvss3Score(vectorOrScore);
    }

    return null;
  }

  /** Calculate CVSS v3.x base score from vector string */
  private calculateCvss3Score(vector: string): number | null {
    // CVSS v3 metric values
    const metricValues: Record<string, Record<string, number>> = {
      AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },       // Attack Vector
      AC: { L: 0.77, H: 0.44 },                         // Attack Complexity
      PR: {                                              // Privileges Required (varies by Scope)
        N_U: 0.85, L_U: 0.62, H_U: 0.27,
        N_C: 0.85, L_C: 0.68, H_C: 0.5,
      },
      UI: { N: 0.85, R: 0.62 },                         // User Interaction
      C: { H: 0.56, L: 0.22, N: 0 },                    // Confidentiality Impact
      I: { H: 0.56, L: 0.22, N: 0 },                    // Integrity Impact
      A: { H: 0.56, L: 0.22, N: 0 },                    // Availability Impact
    };

    // Parse vector string
    const parts = vector.split('/');
    const metrics: Record<string, string> = {};
    for (const part of parts) {
      const [key, value] = part.split(':');
      if (key && value) metrics[key] = value;
    }

    // Extract required metrics
    const av = metricValues.AV[metrics.AV];
    const ac = metricValues.AC[metrics.AC];
    const ui = metricValues.UI[metrics.UI];
    const scope = metrics.S; // 'U' = Unchanged, 'C' = Changed
    const c = metricValues.C[metrics.C];
    const i = metricValues.I[metrics.I];
    const a = metricValues.A[metrics.A];

    // PR depends on Scope
    const prKey = `${metrics.PR}_${scope}`;
    const pr = metricValues.PR[prKey];

    if ([av, ac, pr, ui, c, i, a].some((v) => v === undefined)) {
      return null; // Missing required metrics
    }

    // Calculate Impact Sub Score (ISS)
    const iss = 1 - (1 - c) * (1 - i) * (1 - a);

    // Calculate Impact
    let impact: number;
    if (scope === 'U') {
      impact = 6.42 * iss;
    } else {
      impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
    }

    // Calculate Exploitability
    const exploitability = 8.22 * av * ac * pr * ui;

    // Calculate Base Score
    if (impact <= 0) return 0;

    let baseScore: number;
    if (scope === 'U') {
      baseScore = Math.min(impact + exploitability, 10);
    } else {
      baseScore = Math.min(1.08 * (impact + exploitability), 10);
    }

    // Round up to 1 decimal place (CVSS spec)
    return Math.ceil(baseScore * 10) / 10;
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
      deno: 'JSR', // JSR packages (Deno registry)
    };
    return map[ecosystem] ?? ecosystem;
  }
}

// ─── OSV API Response Types ─────────────────────────────────────

/** Response from /v1/querybatch - returns minimal vuln info (just id and modified) */
interface OsvBatchResponse {
  results: Array<{
    vulns?: OsvBatchVuln[];
  }>;
}

/** Minimal vulnerability info returned by /v1/querybatch */
interface OsvBatchVuln {
  id: string;
  modified?: string;
}

/** Full vulnerability details from /v1/vulns/{id} */
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
