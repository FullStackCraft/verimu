import { describe, it, expect, vi } from 'vitest';
import { OsvSource } from '../../src/cve/osv.js';
import type { Dependency } from '../../src/core/types.js';

/** Creates a mock fetch that returns a given OSV batch response */
function mockFetch(response: any) {
  return vi.fn().mockResolvedValue({
    ok: true,
    json: () => Promise.resolve(response),
  }) as unknown as typeof fetch;
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

    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, options] = fetchMock.mock.calls[0];
    expect(url).toBe('https://api.osv.dev/v1/querybatch');
    expect(options.method).toBe('POST');

    const body = JSON.parse(options.body);
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

  it('maps OSV vulnerabilities to our Vulnerability type', async () => {
    const fetchMock = mockFetch({
      results: [
        {
          vulns: [
            {
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
                      events: [
                        { introduced: '0' },
                        { fixed: '4.19.2' },
                      ],
                    },
                  ],
                },
              ],
            },
          ],
        },
        {}, // lodash — no vulns
        {}, // jsonwebtoken — no vulns
      ],
    });

    const osv = new OsvSource(fetchMock);
    const vulns = await osv.checkDependencies(testDeps);

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
    const fetchMock = mockFetch({
      results: [
        {
          vulns: [
            {
              id: 'CVE-2024-0001',
              summary: 'First vuln',
              severity: [{ type: 'CVSS_V3', score: '9.8' }],
            },
            {
              id: 'CVE-2024-0002',
              summary: 'Second vuln',
              severity: [{ type: 'CVSS_V3', score: '5.3' }],
            },
          ],
        },
        {},
        {},
      ],
    });

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
    }) as unknown as typeof fetch;

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
    const fetchMock = mockFetch({
      results: [
        {
          vulns: [
            {
              id: 'GHSA-xxxx-yyyy-zzzz',
              summary: 'Some vuln without CVE',
            },
          ],
        },
        {},
        {},
      ],
    });

    const osv = new OsvSource(fetchMock);
    const vulns = await osv.checkDependencies(testDeps);
    expect(vulns[0].id).toBe('GHSA-xxxx-yyyy-zzzz');
  });
});
