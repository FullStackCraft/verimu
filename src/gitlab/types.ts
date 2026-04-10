/**
 * Types for the GitLab integration — remote scanning of self-hosted
 * or cloud GitLab instances.
 */

import type { VerimuReport, Severity } from '../core/types.js';

// ─── GitLab API Types ───────────────────────────────────────────

/** GitLab project as returned by /api/v4/projects */
export interface GitLabProject {
  id: number;
  name: string;
  name_with_namespace: string;
  path: string;
  path_with_namespace: string;
  description: string | null;
  http_url_to_repo: string;
  ssh_url_to_repo: string;
  web_url: string;
  default_branch: string;
  archived: boolean;
  empty_repo: boolean;
  visibility: 'private' | 'internal' | 'public';
  last_activity_at: string;
  namespace: {
    id: number;
    name: string;
    path: string;
    kind: 'group' | 'user';
    full_path: string;
  };
}

/** GitLab group as returned by /api/v4/groups */
export interface GitLabGroup {
  id: number;
  name: string;
  path: string;
  full_path: string;
  description: string | null;
  web_url: string;
  parent_id: number | null;
}

// ─── GitLab Scan Configuration ──────────────────────────────────

/** Configuration for a GitLab-wide scan */
export interface GitLabScanConfig {
  /** GitLab instance base URL (e.g., https://git.solve.ch) */
  url: string;
  /** Personal access token or deploy token */
  token: string;
  /** Only scan repos in these groups (by path or ID). Empty = all accessible repos. */
  groups?: string[];
  /** Exclude repos matching these patterns (path_with_namespace glob) */
  excludePatterns?: string[];
  /** Skip archived repositories (default: true) */
  excludeArchived?: boolean;
  /** Skip empty repositories (default: true) */
  excludeEmpty?: boolean;
  /** Skip forked repositories (default: false) */
  excludeForks?: boolean;
  /** Maximum number of repos to scan (for testing) */
  maxRepos?: number;
  /** Branch to clone (default: each repo's default branch) */
  branch?: string;
  /** Where to write the HTML report */
  htmlOutput?: string;
  /** Where to write the JSON aggregate report */
  jsonOutput?: string;
  /** Skip CVE checking (just discover dependencies) */
  skipCveCheck?: boolean;
  /** Verimu API key for platform upload */
  apiKey?: string;
  /** Verimu API base URL */
  apiBaseUrl?: string;
  /** Group name for Verimu platform */
  groupName?: string;
  /** Maximum concurrent clone operations */
  concurrency?: number;
}

// ─── GitLab Scan Results ────────────────────────────────────────

/** Result of scanning a single GitLab repo */
export interface GitLabRepoScanResult {
  /** GitLab project metadata */
  project: GitLabProject;
  /** Verimu scan reports (one per discovered project in the repo) */
  reports: VerimuReport[];
  /** Whether any lockfile was found in the repo */
  hasLockfile: boolean;
  /** Error message if scan failed */
  error?: string;
  /** Time taken for this repo (clone + scan + cleanup) in ms */
  durationMs: number;
}

/** Aggregate result of scanning all GitLab repos */
export interface GitLabScanResult {
  /** GitLab instance URL */
  instanceUrl: string;
  /** Total repositories discovered on the instance */
  totalReposDiscovered: number;
  /** Repos that were scanned (had lockfiles) */
  scannedRepos: GitLabRepoScanResult[];
  /** Repos skipped (no lockfile, archived, empty, excluded) */
  skippedRepos: Array<{
    project: GitLabProject;
    reason: string;
  }>;
  /** Repos that failed to scan */
  failedRepos: Array<{
    project: GitLabProject;
    error: string;
  }>;
  /** Aggregate vulnerability summary across all repos */
  summary: {
    totalRepos: number;
    reposWithVulnerabilities: number;
    totalDependencies: number;
    totalVulnerabilities: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    exploitedInWild: number;
    ecosystemBreakdown: Record<string, number>;
  };
  /** Top vulnerabilities by severity (deduped across repos) */
  topVulnerabilities: Array<{
    id: string;
    severity: Severity;
    summary: string;
    affectedRepos: string[];
    fixedVersion?: string;
    exploitedInWild: boolean;
  }>;
  /** Scan timestamp */
  scannedAt: string;
  /** Total scan duration in ms */
  durationMs: number;
}
