import { describe, it, expect } from 'vitest';
import { CveAggregator } from '../../src/cve/aggregator.js';
import type { CveSource } from '../../src/cve/source.interface.js';
import type { Dependency, Vulnerability, VulnerabilitySource } from '../../src/core/types.js';

/** Creates a mock CVE source that returns predefined vulnerabilities */
function createMockSource(
  sourceId: VulnerabilitySource,
  vulns: Vulnerability[]
): CveSource {
  return {
    sourceId,
    name: `Mock ${sourceId}`,
    checkDependencies: async () => vulns,
  };
}

/** Creates a mock CVE source that throws */
function createFailingSource(sourceId: VulnerabilitySource, error: string): CveSource {
  return {
    sourceId,
    name: `Failing ${sourceId}`,
    checkDependencies: async () => {
      throw new Error(error);
    },
  };
}

const testDeps: Dependency[] = [
  { name: 'express', version: '4.18.2', direct: true, ecosystem: 'npm', purl: 'pkg:npm/express@4.18.2' },
];

const baseVuln: Vulnerability = {
  id: 'CVE-2024-1234',
  aliases: [],
  summary: 'Test vulnerability',
  severity: 'HIGH',
  packageName: 'express',
  ecosystem: 'npm',
  exploitedInWild: false,
  source: 'osv',
};

describe('CveAggregator', () => {
  it('merges results from multiple sources', async () => {
    const source1 = createMockSource('osv', [{ ...baseVuln, source: 'osv' }]);
    const source2 = createMockSource('github-advisory', [
      { ...baseVuln, id: 'CVE-2024-5678', source: 'github-advisory', severity: 'MEDIUM' },
    ]);

    const aggregator = new CveAggregator([source1, source2]);
    const result = await aggregator.check(testDeps);

    expect(result.vulnerabilities).toHaveLength(2);
    expect(result.sourcesQueried).toContain('osv');
    expect(result.sourcesQueried).toContain('github-advisory');
  });

  it('deduplicates same CVE from multiple sources', async () => {
    const fromOsv: Vulnerability = {
      ...baseVuln,
      source: 'osv',
      cvssScore: 7.5,
      fixedVersion: undefined,
    };
    const fromGithub: Vulnerability = {
      ...baseVuln,
      source: 'github-advisory',
      cvssScore: undefined,
      fixedVersion: '4.19.2',
    };

    const source1 = createMockSource('osv', [fromOsv]);
    const source2 = createMockSource('github-advisory', [fromGithub]);

    const aggregator = new CveAggregator([source1, source2]);
    const result = await aggregator.check(testDeps);

    // Should be deduplicated to 1
    expect(result.vulnerabilities).toHaveLength(1);

    // Should have the best data from both sources
    const merged = result.vulnerabilities[0];
    expect(merged.cvssScore).toBe(7.5); // from osv
    expect(merged.fixedVersion).toBe('4.19.2'); // from github
  });

  it('handles source failures gracefully (other sources still work)', async () => {
    const source1 = createMockSource('osv', [baseVuln]);
    const source2 = createFailingSource('github-advisory', 'Rate limited');

    const aggregator = new CveAggregator([source1, source2]);
    const result = await aggregator.check(testDeps);

    expect(result.vulnerabilities).toHaveLength(1);
    expect(result.sourcesQueried).toContain('osv');
    expect(result.sourceErrors).toHaveLength(1);
    expect(result.sourceErrors[0].source).toBe('github-advisory');
    expect(result.sourceErrors[0].error).toContain('Rate limited');
  });

  it('tracks check duration', async () => {
    const source1 = createMockSource('osv', []);
    const aggregator = new CveAggregator([source1]);
    const result = await aggregator.check(testDeps);

    expect(result.checkDurationMs).toBeGreaterThanOrEqual(0);
  });

  it('merges exploitedInWild flag correctly', async () => {
    const fromOsv: Vulnerability = { ...baseVuln, exploitedInWild: false };
    const fromCisa: Vulnerability = { ...baseVuln, source: 'cisa-kev', exploitedInWild: true };

    const source1 = createMockSource('osv', [fromOsv]);
    const source2 = createMockSource('cisa-kev', [fromCisa]);

    const aggregator = new CveAggregator([source1, source2]);
    const result = await aggregator.check(testDeps);

    expect(result.vulnerabilities).toHaveLength(1);
    expect(result.vulnerabilities[0].exploitedInWild).toBe(true);
  });
});
