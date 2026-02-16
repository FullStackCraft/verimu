import { describe, it, expect, vi, type Mock } from 'vitest';
import { OsvSource } from '../../src/cve/osv.js';
import type { Dependency } from '../../src/core/types.js';

type MockFetch = Mock<typeof fetch>;

/**
 * Creates a mock fetch that handles both:
 * - POST /querybatch -> returns minimal vuln IDs
 * - GET /vulns/{id} -> returns full vulnerability details
 */
function mockFetch(batchResponse: any, vulnDetails: Record<string, any> = {}): MockFetch {
  return vi.fn().mockImplementation((url: string, options?: RequestInit) => {
    // Handle /querybatch POST
    if (url.includes('/querybatch') && options?.method === 'POST') {
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve(batchResponse),
      });
    }

    // Handle /vulns/{id} GET
    const vulnMatch = url.match(/\/vulns\/(.+)$/);
    if (vulnMatch) {
      const id = decodeURIComponent(vulnMatch[1]);
      const vuln = vulnDetails[id];
      if (vuln) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(vuln),
        });
      }
      return Promise.resolve({
        ok: false,
        status: 404,
        statusText: 'Not Found',
      });
    }

    return Promise.resolve({
      ok: false,
      status: 404,
      statusText: 'Not Found',
    });
  }) as MockFetch;
}

const testDeps: Dependency[] = [
  { name: 'express', version: '4.18.2', direct: true, ecosystem: 'npm', purl: 'pkg:npm/express@4.18.2' },
  { name: 'lodash', version: '4.17.21', direct: true, ecosystem: 'npm', purl: 'pkg:npm/lodash@4.17.21' },
  { name: 'jsonwebtoken', version: '9.0.0', direct: true, ecosystem: 'npm', purl: 'pkg:npm/jsonwebtoken@9.0.0' },
];

describe('OsvSource', () => {
  it('sends correct batch query to OSV API', async () => {
    const fetchMock = mockFetch({ results: [{}, {}, {}] });
    const osv = new OsvSource(fetchMock);

    await osv.checkDependencies(testDeps);

    // First call should be to querybatch
    const [url, options] = fetchMock.mock.calls[0];
    expect(url).toBe('https://api.osv.dev/v1/querybatch');
    expect(options!.method).toBe('POST');

    const body = JSON.parse(options!.body as string);
    expect(body.queries).toHaveLength(3);
    expect(body.queries[0]).toEqual({
      version: '4.18.2',
      package: { name: 'express', ecosystem: 'npm' },
    });
  });

  it('returns empty array when no vulns found', async () => {
    const fetchMock = mockFetch({ results: [{}, {}, {}] });
    const osv = new OsvSource(fetchMock);

    const vulns = await osv.checkDependencies(testDeps);
    expect(vulns).toHaveLength(0);
  });

  it('fetches full vulnerability details and maps to our Vulnerability type', async () => {
    const batchResponse = {
      results: [
        {
          vulns: [{ id: 'GHSA-rv95-896h-c2yt', modified: '2024-03-25T00:00:00Z' }],
        },
        {}, // lodash — no vulns
        {}, // jsonwebtoken — no vulns
      ],
    };

    const vulnDetails = {
      'GHSA-rv95-896h-c2yt': {
        id: 'GHSA-rv95-896h-c2yt',
        aliases: ['CVE-2024-29041'],
        summary: 'Express.js open redirect vulnerability',
        severity: [{ type: 'CVSS_V3', score: '6.1' }],
        published: '2024-03-25T00:00:00Z',
        affected: [
          {
            package: { name: 'express', ecosystem: 'npm' },
            ranges: [
              {
                type: 'SEMVER',
                events: [{ introduced: '0' }, { fixed: '4.19.2' }],
              },
            ],
          },
        ],
      },
    };

    const fetchMock = mockFetch(batchResponse, vulnDetails);
    const osv = new OsvSource(fetchMock);
    const vulns = await osv.checkDependencies(testDeps);

    // Should have called querybatch once, then vulns/{id} once
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock.mock.calls[1][0]).toBe('https://api.osv.dev/v1/vulns/GHSA-rv95-896h-c2yt');

    expect(vulns).toHaveLength(1);
    const vuln = vulns[0];
    expect(vuln.id).toBe('CVE-2024-29041'); // Prefers CVE ID from aliases
    expect(vuln.aliases).toContain('GHSA-rv95-896h-c2yt');
    expect(vuln.aliases).toContain('CVE-2024-29041');
    expect(vuln.severity).toBe('MEDIUM');
    expect(vuln.cvssScore).toBe(6.1);
    expect(vuln.packageName).toBe('express');
    expect(vuln.fixedVersion).toBe('4.19.2');
    expect(vuln.affectedVersionRange).toBe('>=0, <4.19.2');
    expect(vuln.source).toBe('osv');
    expect(vuln.referenceUrl).toContain('osv.dev');
  });

  it('handles multiple vulns for the same package', async () => {
    const batchResponse = {
      results: [
        {
          vulns: [
            { id: 'CVE-2024-0001', modified: '2024-01-01T00:00:00Z' },
            { id: 'CVE-2024-0002', modified: '2024-01-02T00:00:00Z' },
          ],
        },
        {},
        {},
      ],
    };

    const vulnDetails = {
      'CVE-2024-0001': {
        id: 'CVE-2024-0001',
        summary: 'First vuln',
        severity: [{ type: 'CVSS_V3', score: '9.8' }],
      },
      'CVE-2024-0002': {
        id: 'CVE-2024-0002',
        summary: 'Second vuln',
        severity: [{ type: 'CVSS_V3', score: '5.3' }],
      },
    };

    const fetchMock = mockFetch(batchResponse, vulnDetails);
    const osv = new OsvSource(fetchMock);
    const vulns = await osv.checkDependencies(testDeps);
    expect(vulns).toHaveLength(2);
    expect(vulns[0].severity).toBe('CRITICAL');
    expect(vulns[1].severity).toBe('MEDIUM');
  });

  it('handles API errors gracefully', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: false,
      status: 500,
      statusText: 'Internal Server Error',
    }) as MockFetch;

    const osv = new OsvSource(fetchMock);
    await expect(osv.checkDependencies(testDeps)).rejects.toThrow('OSV API error: 500');
  });

  it('handles empty dependency list', async () => {
    const fetchMock = mockFetch({ results: [] });
    const osv = new OsvSource(fetchMock);
    const vulns = await osv.checkDependencies([]);
    expect(vulns).toHaveLength(0);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('falls back to GHSA ID when no CVE alias exists', async () => {
    const batchResponse = {
      results: [
        {
          vulns: [{ id: 'GHSA-xxxx-yyyy-zzzz', modified: '2024-01-01T00:00:00Z' }],
        },
        {},
        {},
      ],
    };

    const vulnDetails = {
      'GHSA-xxxx-yyyy-zzzz': {
        id: 'GHSA-xxxx-yyyy-zzzz',
        summary: 'Some vuln without CVE',
      },
    };

    const fetchMock = mockFetch(batchResponse, vulnDetails);
    const osv = new OsvSource(fetchMock);
    const vulns = await osv.checkDependencies(testDeps);
    expect(vulns[0].id).toBe('GHSA-xxxx-yyyy-zzzz');
  });

  it('deduplicates vulnerability IDs across multiple affected packages', async () => {
    // Same vuln affects both express and lodash
    const batchResponse = {
      results: [
        { vulns: [{ id: 'CVE-2024-SHARED', modified: '2024-01-01T00:00:00Z' }] },
        { vulns: [{ id: 'CVE-2024-SHARED', modified: '2024-01-01T00:00:00Z' }] },
        {},
      ],
    };

    const vulnDetails = {
      'CVE-2024-SHARED': {
        id: 'CVE-2024-SHARED',
        summary: 'Shared vulnerability',
        severity: [{ type: 'CVSS_V3', score: '7.5' }],
      },
    };

    const fetchMock = mockFetch(batchResponse, vulnDetails);
    const osv = new OsvSource(fetchMock);
    const vulns = await osv.checkDependencies(testDeps);

    // Should only fetch the vuln once but create entries for both affected packages
    const vulnFetchCalls = fetchMock.mock.calls.filter((call: any[]) =>
      call[0].includes('/vulns/')
    );
    expect(vulnFetchCalls).toHaveLength(1); // Only one fetch for the shared vuln

    // But two vulnerability entries (one per affected package)
    expect(vulns).toHaveLength(2);
    expect(vulns[0].packageName).toBe('express');
    expect(vulns[1].packageName).toBe('lodash');
  });

  it('continues if individual vuln fetch fails', async () => {
    const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => { });

    const batchResponse = {
      results: [
        {
          vulns: [
            { id: 'CVE-2024-GOOD', modified: '2024-01-01T00:00:00Z' },
            { id: 'CVE-2024-BAD', modified: '2024-01-02T00:00:00Z' },
          ],
        },
        {},
        {},
      ],
    };

    const vulnDetails = {
      'CVE-2024-GOOD': {
        id: 'CVE-2024-GOOD',
        summary: 'Good vuln',
        severity: [{ type: 'CVSS_V3', score: '8.0' }],
      },
      // CVE-2024-BAD is missing, will return 404
    };

    const fetchMock = mockFetch(batchResponse, vulnDetails);
    const osv = new OsvSource(fetchMock);
    const vulns = await osv.checkDependencies(testDeps);

    // Should still return the one that succeeded
    expect(vulns).toHaveLength(1);
    expect(vulns[0].id).toBe('CVE-2024-GOOD');

    consoleWarnSpy.mockRestore();
  });
});
