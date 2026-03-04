import type { CveSource } from './source.interface.js';
import type { Dependency, CveCheckResult, Vulnerability, VulnerabilitySource } from '../core/types.js';
import { OsvSource } from './osv.js';

/**
 * Aggregates vulnerability data from multiple CVE sources.
 * Deduplicates results by CVE ID across sources.
 */
export class CveAggregator {
  private sources: CveSource[];

  constructor(sources?: CveSource[]) {
    this.sources = sources ?? [
      new OsvSource(),
      // Future: new NvdSource(), new EuvdSource(), new CisaKevSource()
    ];
  }

  /**
   * Checks dependencies against all registered CVE sources.
   * Runs sources in parallel and merges/deduplicates results.
   */
  async check(dependencies: Dependency[]): Promise<CveCheckResult> {
    const startTime = Date.now();
    const sourcesQueried: VulnerabilitySource[] = [];
    const sourceErrors: { source: VulnerabilitySource; error: string }[] = [];
    const allVulns: Vulnerability[] = [];

    // Run all sources in parallel
    const results = await Promise.allSettled(
      this.sources.map(async (source) => {
        const vulns = await source.checkDependencies(dependencies);
        return { sourceId: source.sourceId, vulns };
      })
    );

    for (const result of results) {
      if (result.status === 'fulfilled') {
        sourcesQueried.push(result.value.sourceId);
        allVulns.push(...result.value.vulns);
      } else {
        // Extract the source ID from the error context
        const sourceIndex = results.indexOf(result);
        const sourceId = this.sources[sourceIndex].sourceId;
        sourceErrors.push({
          source: sourceId,
          error: result.reason instanceof Error ? result.reason.message : String(result.reason),
        });
      }
    }

    // Deduplicate by CVE ID (prefer the entry with more data)
    const deduplicated = this.deduplicateVulnerabilities(allVulns);

    return {
      vulnerabilities: deduplicated,
      sourcesQueried,
      sourceErrors,
      checkDurationMs: Date.now() - startTime,
    };
  }

  /**
   * Deduplicates vulnerabilities by ID.
   * When the same CVE appears from multiple sources,
   * keeps the one with more complete data (has CVSS score, has fix version, etc.)
   */
  private deduplicateVulnerabilities(vulns: Vulnerability[]): Vulnerability[] {
    const byKey = new Map<string, Vulnerability>();

    for (const vuln of vulns) {
      // Key by (vulnerability ID + package name) to handle the same CVE
      // affecting multiple packages
      const key = `${vuln.id}::${vuln.packageName}`;
      const existing = byKey.get(key);

      if (!existing) {
        byKey.set(key, vuln);
      } else {
        // Keep the one with more data
        byKey.set(key, this.pickBetterEntry(existing, vuln));
      }
    }

    return Array.from(byKey.values());
  }

  /** Picks the vulnerability entry with more complete data */
  private pickBetterEntry(a: Vulnerability, b: Vulnerability): Vulnerability {
    let scoreA = 0;
    let scoreB = 0;

    if (a.cvssScore !== undefined) scoreA++;
    if (b.cvssScore !== undefined) scoreB++;
    if (a.fixedVersion) scoreA++;
    if (b.fixedVersion) scoreB++;
    if (a.affectedVersionRange) scoreA++;
    if (b.affectedVersionRange) scoreB++;
    if (a.severity !== 'UNKNOWN') scoreA++;
    if (b.severity !== 'UNKNOWN') scoreB++;

    // Merge: start with the lesser entry, overlay with the better one.
    // Strip undefined/null values so they don't overwrite real data.
    const strip = (obj: Record<string, unknown>) =>
      Object.fromEntries(Object.entries(obj).filter(([, v]) => v !== undefined && v !== null));

    const winner = scoreB > scoreA
      ? { ...strip(a as unknown as Record<string, unknown>), ...strip(b as unknown as Record<string, unknown>) } as unknown as Vulnerability
      : { ...strip(b as unknown as Record<string, unknown>), ...strip(a as unknown as Record<string, unknown>) } as unknown as Vulnerability;

    // Merge aliases
    const allAliases = new Set([...a.aliases, ...b.aliases]);
    winner.aliases = Array.from(allAliases);

    // If either says exploited, it's exploited
    winner.exploitedInWild = a.exploitedInWild || b.exploitedInWild;

    return winner;
  }
}
