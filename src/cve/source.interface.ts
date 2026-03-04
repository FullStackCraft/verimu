import type { Dependency, Vulnerability, VulnerabilitySource } from '../core/types.js';

/**
 * Interface for vulnerability data sources.
 *
 * To add a new CVE source:
 *   1. Create a new file in cve/ (e.g., nvd.ts)
 *   2. Implement this interface
 *   3. Register it in cve/aggregator.ts
 */
export interface CveSource {
  /** Identifier for this source */
  readonly sourceId: VulnerabilitySource;

  /** Human-readable name */
  readonly name: string;

  /**
   * Checks a list of dependencies for known vulnerabilities.
   * Should handle batching internally for efficiency.
   */
  checkDependencies(dependencies: Dependency[]): Promise<Vulnerability[]>;
}
