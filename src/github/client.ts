/**
 * GitHub API client for listing and cloning repositories.
 *
 * Supports github.com and GitHub Enterprise Server (GHES).
 * Handles both authenticated (5,000 req/h) and unauthenticated (60 req/h)
 * rate limits, with automatic wait-and-retry on transient errors.
 */

import { execSync } from 'child_process';
import { mkdtempSync, rmSync, existsSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import type { GitHubRepo, GitHubUser } from './types.js';

// ─── Rate limit info ────────────────────────────────────────────

interface RateLimitInfo {
  limit: number;
  remaining: number;
  resetAt: Date;
  used: number;
}

// ─── Profile parsing ────────────────────────────────────────────

export interface ParsedProfile {
  /** The login/handle extracted from the URL or raw input */
  login: string;
}

/**
 * Parses a GitHub profile input which can be:
 *  - A full URL: https://github.com/octokit
 *  - A URL with trailing slash/params: https://github.com/octokit/?tab=repos
 *  - A bare handle: octokit
 */
export function parseProfile(input: string, baseUrl: string): ParsedProfile {
  const trimmed = input.trim();

  // Try parsing as URL
  try {
    const url = new URL(trimmed);
    // Extract pathname, remove leading/trailing slashes
    const pathSegments = url.pathname.split('/').filter(Boolean);
    if (pathSegments.length >= 1) {
      return { login: pathSegments[0] };
    }
  } catch {
    // Not a URL — fall through to handle as bare login
  }

  // Also try prefixing with baseUrl in case it's a relative URL like "github.com/org"
  if (trimmed.includes('/') && !trimmed.startsWith('http')) {
    try {
      const url = new URL(`https://${trimmed}`);
      const pathSegments = url.pathname.split('/').filter(Boolean);
      if (pathSegments.length >= 1) {
        return { login: pathSegments[0] };
      }
    } catch {
      // Fall through
    }
  }

  // Bare handle
  if (!trimmed || trimmed.includes(' ')) {
    throw new Error(`Invalid GitHub profile: "${input}". Provide an org/user handle or URL.`);
  }

  return { login: trimmed };
}

// ─── Client ─────────────────────────────────────────────────────

export class GitHubClient {
  private baseUrl: string;
  private apiUrl: string;
  private token?: string;
  private lastRateLimit?: RateLimitInfo;

  constructor(baseUrl: string, token?: string) {
    // Normalize: strip trailing slash
    this.baseUrl = baseUrl.replace(/\/+$/, '');
    this.token = token;

    // GitHub.com uses api.github.com; GHES uses <base>/api/v3
    if (this.baseUrl === 'https://github.com' || this.baseUrl === 'http://github.com') {
      this.apiUrl = 'https://api.github.com';
    } else {
      this.apiUrl = `${this.baseUrl}/api/v3`;
    }
  }

  // ─── Owner Type Detection ──────────────────────────────────

  /**
   * Determines whether a login is a User or Organization by
   * calling GET /users/{username} and reading the `type` field.
   */
  async detectOwnerType(login: string): Promise<'org' | 'user'> {
    const data = await this.fetch<GitHubUser>(`${this.apiUrl}/users/${encodeURIComponent(login)}`);

    if (data.type === 'Organization') return 'org';
    return 'user';
  }

  // ─── Repo Listing ──────────────────────────────────────────

  /**
   * Lists repositories for an organization.
   * Uses GET /orgs/{org}/repos with pagination.
   */
  async listOrgRepos(org: string): Promise<GitHubRepo[]> {
    return this.paginate<GitHubRepo>(
      `${this.apiUrl}/orgs/${encodeURIComponent(org)}/repos`,
      { type: 'all', sort: 'pushed', direction: 'desc' }
    );
  }

  /**
   * Lists repositories for a user.
   *
    * - Without token: GET /users/{username}/repos
    *   - default: type=all
    *   - ownerOnly: type=owner
   * - With token for own user: GET /user/repos filtered by owner login
   *   (includes private repos the token can see)
    * - With token for other user: GET /users/{username}/repos
   *   (only public repos visible)
   */
  async listUserRepos(login: string, ownerOnly = false): Promise<GitHubRepo[]> {
    if (this.token) {
      // Try to check if we're the authenticated user
      try {
        const authedUser = await this.fetch<{ login: string }>(`${this.apiUrl}/user`);
        if (authedUser.login.toLowerCase() === login.toLowerCase()) {
          // We're listing our own repos — use /user/repos for private access
          const allRepos = await this.paginate<GitHubRepo>(
            `${this.apiUrl}/user/repos`,
            { sort: 'pushed', direction: 'desc', affiliation: 'owner' }
          );
          return allRepos;
        }
      } catch {
        // Token may not have user scope; fall through to public listing
      }
    }

    // Public listing or listing another user's repos
    return this.paginate<GitHubRepo>(
      `${this.apiUrl}/users/${encodeURIComponent(login)}/repos`,
      { type: ownerOnly ? 'owner' : 'all', sort: 'pushed', direction: 'desc' }
    );
  }

  /**
   * Lists repos based on resolved owner type.
   */
  async listRepos(login: string, ownerType: 'org' | 'user', options?: { ownerOnly?: boolean }): Promise<GitHubRepo[]> {
    if (ownerType === 'org') {
      return this.listOrgRepos(login);
    }
    return this.listUserRepos(login, options?.ownerOnly ?? false);
  }

  // ─── Cloning ───────────────────────────────────────────────

  /**
   * Shallow-clones a repo into a temporary directory.
   * Returns the path to the cloned repo.
   *
   * Uses HTTPS with token auth embedded in the URL (when token is available).
   */
  cloneToTemp(repo: GitHubRepo, branch?: string): string {
    const tempDir = mkdtempSync(join(tmpdir(), `verimu-gh-${repo.id}-`));

    const cloneUrl = this.token
      ? this.buildAuthUrl(repo.clone_url)
      : repo.clone_url;
    const targetBranch = branch ?? repo.default_branch;

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
      this.cleanupTemp(tempDir);
      const msg = err instanceof Error ? err.message : String(err);
      throw new Error(`Clone failed for ${repo.full_name}: ${msg}`);
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

  // ─── Rate Limit Accessors ──────────────────────────────────

  /** Returns the last observed rate limit info, if any. */
  getRateLimit(): RateLimitInfo | undefined {
    return this.lastRateLimit;
  }

  /**
   * Returns the hourly rate limit for this client configuration.
   * - Unauthenticated: 60 requests/hour
   * - Authenticated (PAT/OAuth): 5,000 requests/hour
   */
  getExpectedRateLimit(): number {
    return this.token ? 5_000 : 60;
  }

  // ─── Internals ─────────────────────────────────────────────

  /**
   * Paginated GET — fetches all pages of a list endpoint.
   * GitHub uses `per_page` (max 100) and `page` parameters.
   */
  private async paginate<T>(url: string, params: Record<string, string> = {}): Promise<T[]> {
    const all: T[] = [];
    let page = 1;
    const perPage = 100;

    while (true) {
      const searchParams = new URLSearchParams({
        ...params,
        per_page: String(perPage),
        page: String(page),
      });

      const fullUrl = `${url}?${searchParams.toString()}`;
      const items = await this.fetch<T[]>(fullUrl);

      if (items.length === 0) break;

      all.push(...items);
      page++;

      // If we got fewer than perPage, we've hit the last page
      if (items.length < perPage) break;
    }

    return all;
  }

  /**
   * Builds an authenticated HTTPS URL for git clone.
   * Embeds the token as a password with "x-access-token" user.
   */
  private buildAuthUrl(httpUrl: string): string {
    const url = new URL(httpUrl);
    url.username = 'x-access-token';
    url.password = this.token!;
    return url.toString();
  }

  /**
   * Makes an authenticated GET request to the GitHub API.
   *
   * Rate limit handling:
   * - Reads X-RateLimit-Remaining and X-RateLimit-Reset headers
   * - If remaining is 0, waits until the reset time or throws with actionable message
   * - Retries on transient 502/503/504 with exponential backoff (up to 3 retries)
   * - Returns 403/429 rate limit errors with reset time information
   */
  private async fetch<T>(url: string): Promise<T> {
    const maxRetries = 3;
    let lastError: Error | null = null;

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      // Check if we know we're rate limited before making the request
      if (this.lastRateLimit && this.lastRateLimit.remaining === 0) {
        const now = Date.now();
        const resetMs = this.lastRateLimit.resetAt.getTime();
        if (now < resetMs) {
          const waitSec = Math.ceil((resetMs - now) / 1000);
          // Only auto-wait if reset is within 60 seconds; otherwise throw
          if (waitSec <= 60) {
            console.log(`    Rate limit reached. Waiting ${waitSec}s for reset...`);
            await this.sleep(waitSec * 1000);
          } else {
            throw new Error(
              `GitHub API rate limit exceeded. ` +
              `Limit: ${this.lastRateLimit.limit} requests/hour` +
              `${this.token ? '' : ' (unauthenticated — use --token for 5,000/hour)'}. ` +
              `Resets at ${this.lastRateLimit.resetAt.toLocaleTimeString()} ` +
              `(${waitSec}s from now).`
            );
          }
        }
      }

      const headers: Record<string, string> = {
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
      };

      if (this.token) {
        headers['Authorization'] = `Bearer ${this.token}`;
      }

      let response: Response;
      try {
        response = await globalThis.fetch(url, { headers });
      } catch (err: unknown) {
        lastError = err instanceof Error ? err : new Error(String(err));
        if (attempt < maxRetries) {
          await this.sleep(1000 * 2 ** attempt);
          continue;
        }
        throw lastError;
      }

      // Parse rate limit headers
      this.updateRateLimit(response);

      // Success
      if (response.ok) {
        return response.json() as Promise<T>;
      }

      // Rate limit hit (403 or 429)
      if (response.status === 403 || response.status === 429) {
        const body = await response.text().catch(() => 'no body');

        // Check if it's actually a rate limit (vs. permission denied)
        if (body.includes('rate limit') || body.includes('API rate limit') || response.status === 429) {
          const resetHeader = response.headers.get('X-RateLimit-Reset');
          const resetAt = resetHeader
            ? new Date(Number(resetHeader) * 1000)
            : new Date(Date.now() + 60_000);
          const waitSec = Math.ceil((resetAt.getTime() - Date.now()) / 1000);

          // If it's the retry-after header, use that
          const retryAfter = response.headers.get('Retry-After');
          if (retryAfter && attempt < maxRetries) {
            const waitMs = Number(retryAfter) * 1000;
            console.log(`    Rate limited (secondary). Waiting ${retryAfter}s...`);
            await this.sleep(Math.min(waitMs, 60_000));
            continue;
          }

          throw new Error(
            `GitHub API rate limit exceeded (${response.status}). ` +
            `${this.token ? '' : 'Unauthenticated requests are limited to 60/hour — use --token for 5,000/hour. '}` +
            `Resets at ${resetAt.toLocaleTimeString()} (${Math.max(0, waitSec)}s from now).`
          );
        }

        // Permission denied (not rate limit)
        throw new Error(
          `GitHub API error: ${response.status} ${response.statusText} — ${url}\n${body}`
        );
      }

      // Transient server errors — retry with backoff
      if ([502, 503, 504].includes(response.status) && attempt < maxRetries) {
        lastError = new Error(`GitHub API error: ${response.status} ${response.statusText}`);
        await this.sleep(1000 * 2 ** attempt);
        continue;
      }

      // Other errors — throw immediately
      const body = await response.text().catch(() => 'no body');
      throw new Error(
        `GitHub API error: ${response.status} ${response.statusText} — ${url}\n${body}`
      );
    }

    throw lastError ?? new Error(`GitHub API request failed after ${maxRetries} retries`);
  }

  /**
   * Updates internal rate limit tracker from response headers.
   */
  private updateRateLimit(response: Response): void {
    const limit = response.headers.get('X-RateLimit-Limit');
    const remaining = response.headers.get('X-RateLimit-Remaining');
    const reset = response.headers.get('X-RateLimit-Reset');
    const used = response.headers.get('X-RateLimit-Used');

    if (limit && remaining && reset) {
      this.lastRateLimit = {
        limit: Number(limit),
        remaining: Number(remaining),
        resetAt: new Date(Number(reset) * 1000),
        used: used ? Number(used) : 0,
      };
    }
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}
