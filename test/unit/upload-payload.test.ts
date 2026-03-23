import { afterEach, describe, expect, it, vi } from 'vitest';
import { uploadToVerimu } from '../../src/scan.js';
import type { VerimuReport } from '../../src/core/types.js';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function buildReport(overrides?: Partial<VerimuReport>): VerimuReport {
  return {
    project: {
      path: '/tmp/my-app',
      ecosystem: 'npm',
      dependencyCount: 1,
    },
    sbom: {
      format: 'cyclonedx-json',
      specVersion: '1.7',
      content: '{}',
      componentCount: 1,
      generatedAt: new Date().toISOString(),
    },
    artifacts: {
      cyclonedx: {
        format: 'cyclonedx-json',
        specVersion: '1.7',
        content: '{"bomFormat":"CycloneDX","specVersion":"1.7","components":[]}',
        componentCount: 0,
        generatedAt: new Date().toISOString(),
      },
      spdx: {
        format: 'spdx-json',
        specVersion: '2.3',
        content: '{"spdxVersion":"SPDX-2.3"}',
        componentCount: 0,
        generatedAt: new Date().toISOString(),
      },
      swid: {
        format: 'swid-xml',
        specVersion: '1.0',
        content: '<SoftwareIdentity/>',
        componentCount: 0,
        generatedAt: new Date().toISOString(),
      },
    },
    cveCheck: {
      vulnerabilities: [],
      sourcesQueried: ['osv'],
      sourceErrors: [],
      checkDurationMs: 10,
    },
    usageContext: {
      triggered: true,
      durationMs: 12,
      numContextLines: 4,
      maxSnippetsPerPackage: 20,
      maxSnippetsTotal: 500,
      totalSnippets: 1,
      artifactPath: '/tmp/sbom.usage-context.json',
      packageFindings: [
        {
          vulnerabilityId: 'CVE-2024-1234',
          packageName: 'express',
          ecosystem: 'npm',
          directDependency: true,
          status: 'direct_evidence',
          snippets: [
            {
              filePath: 'src/index.ts',
              startLine: 1,
              endLine: 4,
              code: 'import express from "express";',
              matchKind: 'import',
              confidence: 0.9,
            },
          ],
          evidenceCount: 1,
        },
      ],
      ecosystemStatus: [
        {
          ecosystem: 'npm',
          analyzer: 'js-ast-analyzer',
          status: 'analyzed',
          vulnerablePackages: 1,
          snippetsFound: 1,
        },
      ],
      errors: [],
      llmPayload: [],
    },
    summary: {
      totalDependencies: 1,
      totalVulnerabilities: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      exploitedInWild: 0,
    },
    generatedAt: new Date().toISOString(),
    ...overrides,
  };
}

function mockUploadRoundtrip() {
  return vi
    .fn()
    .mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        project: {
          id: 'project-1',
          name: 'my-app',
          ecosystem: 'npm',
          repository_url: null,
          platform: null,
        },
        created: false,
      }),
    })
    .mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        project: { id: 'project-1', name: 'my-app' },
        scan_results: [],
        summary: {
          total_dependencies: 1,
          vulnerable_dependencies: 0,
        },
      }),
    });
}

describe('upload payload usage-context fields', () => {
  it('includes usage_context and strips local artifactPath', async () => {
    const fetchMock = mockUploadRoundtrip();
    vi.stubGlobal('fetch', fetchMock as unknown as typeof fetch);

    await uploadToVerimu(buildReport(), {
      projectPath: '/tmp/my-app',
      apiKey: 'vmu_test',
      apiBaseUrl: 'https://api.example.com',
    });

    expect(fetchMock).toHaveBeenCalledTimes(2);
    const secondRequest = fetchMock.mock.calls[1]?.[1] as RequestInit;
    const body = JSON.parse(String(secondRequest.body));

    expect(body.usage_context).toBeDefined();
    expect(body.usage_context.triggered).toBe(true);
    expect(body.usage_context.artifactPath).toBeUndefined();
  });

  it('omits usage_context when the report has none', async () => {
    const fetchMock = mockUploadRoundtrip();
    vi.stubGlobal('fetch', fetchMock as unknown as typeof fetch);

    await uploadToVerimu(buildReport({ usageContext: undefined }), {
      projectPath: '/tmp/my-app',
      apiKey: 'vmu_test',
      apiBaseUrl: 'https://api.example.com',
    });

    const secondRequest = fetchMock.mock.calls[1]?.[1] as RequestInit;
    const body = JSON.parse(String(secondRequest.body));
    expect('usage_context' in body).toBe(false);
  });
});

