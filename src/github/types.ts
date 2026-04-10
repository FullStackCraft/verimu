/**
 * Types for the GitHub integration — remote scanning of GitHub.com
 * or GitHub Enterprise Server (GHES) instances.
 */

import type { VerimuReport, Severity } from '../core/types.js';

// ─── GitHub API Types ───────────────────────────────────────────

/** GitHub repository as returned by the REST API */
export interface GitHubRepo {
  id: number;
  name: string;
  full_name: string;
  private: boolean;
  fork: boolean;
  archived: boolean;
  default_branch: string;
  html_url: string;
  clone_url: string;
  owner: {
    login: string;
    type: 'User' | 'Organization';
  };
}

/** GitHub user/org info as returned by GET /users/{username} */
export interface GitHubUser {
  login: string;
  id: number;
  type: 'User' | 'Organization';
  name: string | null;
  public_repos: number;
}

// ─── GitHub Scan Configuration ──────────────────────────────────

/** Configuration for a GitHub-wide scan */
export interface GitHubScanConfig {
  /** GitHub base URL (default: https://github.com, supports GHES) */
  baseUrl: string;
  /** Org/user profile to enumerate repos (URL or handle) */
  profile: string;
  /** Personal access token or fine-grained token */
  token?: string;
  /** For user profiles, list only owner repositories (default: false) */
  ownerOnly?: boolean;
  /** Exclude forked repositories (default: false) */
  excludeForks?: boolean;
  /** Exclude archived repositories (default: true) */
  excludeArchived?: boolean;
  /** Maximum number of repos to scan */
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
}

// ─── GitHub Scan Results ────────────────────────────────────────

/** Result of scanning a single GitHub repo */
export interface GitHubRepoScanResult {
  /** GitHub repo metadata */
  repo: GitHubRepo;
  /** Verimu scan reports (one per discovered project in the repo) */
  reports: VerimuReport[];
  /** Whether any lockfile was found in the repo */
  hasLockfile: boolean;
  /** Error message if scan failed */
  error?: string;
  /** Time taken for this repo (clone + scan + cleanup) in ms */
  durationMs: number;
}

/** Aggregate result of scanning all GitHub repos */
export interface GitHubScanResult {
  /** GitHub base URL */
  instanceUrl: string;
  /** Profile that was scanned (org or user login) */
  profile: string;
  /** Owner type that was resolved */
  profileType: 'org' | 'user';
  /** Total repositories discovered */
  totalReposDiscovered: number;
  /** Repos that were scanned (had lockfiles) */
  scannedRepos: GitHubRepoScanResult[];
  /** Repos skipped (no lockfile, archived, forked, excluded) */
  skippedRepos: Array<{
    repo: GitHubRepo;
    reason: string;
  }>;
  /** Repos that failed to scan */
  failedRepos: Array<{
    repo: GitHubRepo;
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
