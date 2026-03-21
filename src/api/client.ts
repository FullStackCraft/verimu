/**
 * Verimu API client — communicates with the Verimu backend.
 *
 * Used by the CLI and scan pipeline to:
 *   1. Upsert a project (create-if-not-exists)
 *   2. Upload SBOM + trigger CVE scan
 */

import type { Ecosystem, UsageContextResult } from '../core/types.js';

const DEFAULT_API_BASE = 'https://api.verimu.com';

export interface UpsertProjectResponse {
  project: {
    id: string;
    name: string;
    ecosystem: string;
    repository_url: string | null;
    platform: string | null;
  };
  created: boolean;
}

export interface ScanResponse {
  project: {
    id: string;
    name: string;
  };
  scan_results: Array<{
    dependency_id: string;
    dependency_name: string;
    version: string;
    vulnerabilities: Array<{
      cve_id: string;
      severity?: string | null;
      summary?: string | null;
      description?: string | null;
      fixed_version?: string | null;
      sources?: Array<{
        name?: string;
        url?: string;
        data?: {
          fixed_version?: string | null;
        } | null;
      }> | null;
    }> | null;
  }>;
  summary: {
    total_dependencies: number;
    vulnerable_dependencies: number;
  };
}

export interface SbomUploadBundle {
  cyclonedx: Record<string, unknown>;
  spdx?: Record<string, unknown>;
  swid?: string;
  usage_context?: Omit<UsageContextResult, 'artifactPath'>;
}

export class VerimuApiClient {
  private readonly baseUrl: string;
  private readonly apiKey: string;

  constructor(apiKey: string, baseUrl?: string) {
    this.apiKey = apiKey;
    this.baseUrl = (baseUrl ?? DEFAULT_API_BASE).replace(/\/+$/, '');
  }

  /**
   * Upsert a project — finds by name or creates it.
   * Used so `npx verimu` auto-registers projects without manual dashboard setup.
   */
  async upsertProject(opts: {
    name: string;
    ecosystem: Ecosystem;
    repositoryUrl?: string;
    platform?: string;
  }): Promise<UpsertProjectResponse> {
    const res = await fetch(`${this.baseUrl}/api/projects/upsert`, {
      method: 'POST',
      headers: this.headers(),
      body: JSON.stringify({
        name: opts.name,
        ecosystem: this.mapEcosystem(opts.ecosystem),
        repository_url: opts.repositoryUrl ?? null,
        platform: opts.platform ?? null,
      }),
    });

    if (!res.ok) {
      const body = await res.text();
      throw new Error(`Verimu API: upsert project failed (${res.status}): ${body}`);
    }

    return res.json() as Promise<UpsertProjectResponse>;
  }

  /**
   * Upload a software inventory artifact payload to a project and trigger CVE scanning.
   *
   * Backward-compatible:
   * - string payloads are treated as legacy raw CycloneDX JSON
   * - object payloads can include CycloneDX + SPDX + SWID together
   */
  async uploadSbom(projectId: string, payload: string | SbomUploadBundle): Promise<ScanResponse> {
    const body = typeof payload === 'string'
      ? JSON.stringify(JSON.parse(payload))
      : JSON.stringify(payload);

    const res = await fetch(`${this.baseUrl}/api/projects/${projectId}/scan`, {
      method: 'POST',
      headers: this.headers(),
      body,
    });

    if (!res.ok) {
      const body = await res.text();
      throw new Error(`Verimu API: upload SBOM failed (${res.status}): ${body}`);
    }

    return res.json() as Promise<ScanResponse>;
  }

  private headers(): Record<string, string> {
    return {
      'Content-Type': 'application/json',
      'X-API-Key': this.apiKey,
    };
  }

  /**
   * Maps internal ecosystem names to what the backend expects.
   * Currently 1:1, but keeps the mapping explicit.
   */
  private mapEcosystem(eco: Ecosystem): string {
    const map: Record<Ecosystem, string> = {
      npm: 'npm',
      pip: 'pip',
      poetry: 'poetry',
      uv: 'uv',
      maven: 'maven',
      nuget: 'nuget',
      go: 'gomod',
      cargo: 'cargo',
      ruby: 'bundler',
      composer: 'composer',
      deno: 'deno',
    };
    return map[eco] ?? eco;
  }
}
