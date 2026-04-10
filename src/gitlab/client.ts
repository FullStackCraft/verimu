/**
 * GitLab API client for listing and cloning repositories.
 *
 * Designed for self-hosted GitLab instances (e.g., git.solve.ch)
 * but works with gitlab.com as well.
 */

import { execSync } from 'child_process';
import { mkdtempSync, rmSync, existsSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import type { GitLabProject, GitLabGroup } from './types.js';

export class GitLabClient {
  private baseUrl: string;
  private token: string;
  private apiUrl: string;

  constructor(baseUrl: string, token: string) {
    // Normalize: strip trailing slash
    this.baseUrl = baseUrl.replace(/\/+$/, '');
    this.token = token;
    this.apiUrl = `${this.baseUrl}/api/v4`;
  }

  // ─── Project Listing ────────────────────────────────────────

  /**
   * Lists all accessible projects, paginated.
   * Returns all pages concatenated.
   */
  async listAllProjects(options?: {
    archived?: boolean;
    perPage?: number;
    maxPages?: number;
  }): Promise<GitLabProject[]> {
    const perPage = options?.perPage ?? 100;
    const maxPages = options?.maxPages ?? 100;
    const allProjects: GitLabProject[] = [];

    let page = 1;
    while (page <= maxPages) {
      const params = new URLSearchParams({
        per_page: String(perPage),
        page: String(page),
        order_by: 'last_activity_at',
        sort: 'desc',
        simple: 'false',
      });

      if (options?.archived !== undefined) {
        params.set('archived', String(options.archived));
      }

      const url = `${this.apiUrl}/projects?${params.toString()}`;
      const projects = await this.fetch<GitLabProject[]>(url);

      if (projects.length === 0) break;

      allProjects.push(...projects);
      page++;

      // If we got fewer than perPage, we've hit the last page
      if (projects.length < perPage) break;
    }

    return allProjects;
  }

  /**
   * Lists projects within a specific group (and its subgroups).
   */
  async listGroupProjects(
    groupPath: string,
    options?: { includeSubgroups?: boolean; perPage?: number }
  ): Promise<GitLabProject[]> {
    const perPage = options?.perPage ?? 100;
    const includeSubgroups = options?.includeSubgroups ?? true;
    const allProjects: GitLabProject[] = [];

    let page = 1;
    while (true) {
      const params = new URLSearchParams({
        per_page: String(perPage),
        page: String(page),
        include_subgroups: String(includeSubgroups),
        order_by: 'last_activity_at',
        sort: 'desc',
      });

      const encoded = encodeURIComponent(groupPath);
      const url = `${this.apiUrl}/groups/${encoded}/projects?${params.toString()}`;
      const projects = await this.fetch<GitLabProject[]>(url);

      if (projects.length === 0) break;

      allProjects.push(...projects);
      page++;

      if (projects.length < perPage) break;
    }

    return allProjects;
  }

  /**
   * Lists all groups accessible to the token.
   */
  async listGroups(): Promise<GitLabGroup[]> {
    const allGroups: GitLabGroup[] = [];
    let page = 1;

    while (true) {
      const params = new URLSearchParams({
        per_page: '100',
        page: String(page),
      });

      const url = `${this.apiUrl}/groups?${params.toString()}`;
      const groups = await this.fetch<GitLabGroup[]>(url);

      if (groups.length === 0) break;
      allGroups.push(...groups);
      page++;

      if (groups.length < 100) break;
    }

    return allGroups;
  }

  // ─── Cloning ────────────────────────────────────────────────

  /**
   * Shallow-clones a repo into a temporary directory.
   * Returns the path to the cloned repo.
   *
   * Uses HTTPS with token auth embedded in the URL
   * (works for self-hosted GitLab with private-token).
   */
  cloneToTemp(project: GitLabProject, branch?: string): string {
    const tempDir = mkdtempSync(join(tmpdir(), `verimu-gl-${project.id}-`));

    // Build authenticated clone URL:
    // https://oauth2:<token>@git.solve.ch/group/project.git
    const cloneUrl = this.buildAuthUrl(project.http_url_to_repo);
    const targetBranch = branch ?? project.default_branch;

    try {
      execSync(
        `git clone --depth 1 --branch "${targetBranch}" --single-branch "${cloneUrl}" "${tempDir}"`,
        {
          stdio: 'pipe',
          timeout: 120_000, // 2 minute timeout per clone
          env: {
            ...process.env,
            GIT_TERMINAL_PROMPT: '0', // Never prompt for auth
          },
        }
      );
    } catch (err: unknown) {
      // Clean up on clone failure
      this.cleanupTemp(tempDir);
      const msg = err instanceof Error ? err.message : String(err);
      throw new Error(`Clone failed for ${project.path_with_namespace}: ${msg}`);
    }

    return tempDir;
  }

  /**
   * Removes a temporary clone directory.
   */
  cleanupTemp(tempDir: string): void {
    if (existsSync(tempDir)) {
      rmSync(tempDir, { recursive: true, force: true });
    }
  }

  // ─── Helpers ────────────────────────────────────────────────

  /**
   * Builds an authenticated HTTPS URL for git clone.
   * Embeds the token as oauth2 password.
   */
  private buildAuthUrl(httpUrl: string): string {
    const url = new URL(httpUrl);
    url.username = 'oauth2';
    url.password = this.token;
    return url.toString();
  }

  /**
   * Makes an authenticated GET request to the GitLab API.
   */
  private async fetch<T>(url: string): Promise<T> {
    const response = await globalThis.fetch(url, {
      headers: {
        'PRIVATE-TOKEN': this.token,
        'Accept': 'application/json',
      },
    });

    if (!response.ok) {
      const body = await response.text().catch(() => 'no body');
      throw new Error(
        `GitLab API error: ${response.status} ${response.statusText} — ${url}\n${body}`
      );
    }

    return response.json() as Promise<T>;
  }
}
