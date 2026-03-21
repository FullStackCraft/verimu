import { afterEach, describe, expect, it, vi } from 'vitest';
import { existsSync, unlinkSync } from 'fs';
import { readFile } from 'fs/promises';
import path from 'path';
import { scan } from '../../src/scan.js';

const FIXTURES = path.resolve(__dirname, '../fixtures');
const PROJECT = path.join(FIXTURES, 'vuln-node-usage');
const OUTPUT = path.join(PROJECT, 'test-sbom.cdx.json');

function relatedArtifactPaths(cycloneDxOutput: string) {
  return {
    spdx: cycloneDxOutput.replace(/\.cdx\.json$/, '.spdx.json'),
    swid: cycloneDxOutput.replace(/\.cdx\.json$/, '.swid.xml'),
    usageContext: cycloneDxOutput.replace(/\.cdx\.json$/, '.usage-context.json'),
  };
}

function cleanupArtifacts(cycloneDxOutput: string) {
  const related = relatedArtifactPaths(cycloneDxOutput);
  const paths = [cycloneDxOutput, related.spdx, related.swid, related.usageContext];
  for (const filePath of paths) {
    if (existsSync(filePath)) unlinkSync(filePath);
  }
}

afterEach(() => {
  cleanupArtifacts(OUTPUT);
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('scan usage-context integration', () => {
  it('runs usage analysis when vulnerabilities are found and writes usage artifact', async () => {
    const fetchMock = vi.fn().mockImplementation((url: string, options?: RequestInit) => {
      if (url.includes('/querybatch') && options?.method === 'POST') {
        return Promise.resolve({
          ok: true,
          json: async () => ({
            results: [
              {
                vulns: [{ id: 'GHSA-rv95-896h-c2yt', modified: '2024-03-25T00:00:00Z' }],
              },
            ],
          }),
        });
      }

      if (url.includes('/vulns/GHSA-rv95-896h-c2yt')) {
        return Promise.resolve({
          ok: true,
          json: async () => ({
            id: 'GHSA-rv95-896h-c2yt',
            aliases: ['CVE-2024-29041'],
            summary: 'Express open redirect',
            severity: [{ type: 'CVSS_V3', score: '6.1' }],
            affected: [
              {
                package: { name: 'express', ecosystem: 'npm' },
                ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.19.2' }] }],
              },
            ],
          }),
        });
      }

      return Promise.resolve({ ok: false, status: 404, statusText: 'Not Found' });
    });

    vi.stubGlobal('fetch', fetchMock as unknown as typeof fetch);

    const report = await scan({
      projectPath: PROJECT,
      sbomOutput: OUTPUT,
      skipCveCheck: false,
      numContextLines: 2,
    });

    expect(report.cveCheck.vulnerabilities.length).toBeGreaterThan(0);
    expect(report.usageContext?.triggered).toBe(true);
    expect(report.usageContext?.numContextLines).toBe(2);
    expect(report.usageContext?.packageFindings.length).toBeGreaterThan(0);

    const expressFinding = report.usageContext?.packageFindings.find((f) => f.packageName === 'express');
    expect(expressFinding).toBeDefined();
    expect(expressFinding?.status).toBe('direct_evidence');
    expect(expressFinding?.snippets.length).toBeGreaterThan(0);

    const usageContextPath = relatedArtifactPaths(OUTPUT).usageContext;
    expect(existsSync(usageContextPath)).toBe(true);

    const written = JSON.parse(await readFile(usageContextPath, 'utf-8'));
    expect(written.triggered).toBe(true);
    expect(written.numContextLines).toBe(2);
    expect(written.packageFindings.some((f: any) => f.packageName === 'express')).toBe(true);
  });
});
