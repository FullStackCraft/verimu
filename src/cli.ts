

/**
 * Verimu CLI — CRA compliance scanner.
 *
 * Usage:
 *   npx verimu                        # scan current directory
 *   npx verimu scan                   # explicit scan command
 *   npx verimu scan --path ./myapp    # scan specific directory
 *   npx verimu generate-sbom          # inventory artifacts only, no CVE check
 *
 * Environment:
 *   VERIMU_API_KEY     — API key for Verimu platform (enables upload + monitoring)
 *   VERIMU_API_URL     — Custom API base URL (default: https://api.verimu.com)
 *
 * Exit codes:
 *   0  — scan passed (or no vulnerabilities above threshold)
 *   1  — scan failed (vulnerabilities above threshold)
 *   2  — runtime error (missing lockfile, network error, etc.)
 */

import { resolve } from 'path';
import { writeFile } from 'fs/promises';
import { createRequire } from 'module';
import { scan, shouldFailCi, uploadToVerimu } from './scan.js';
import { ConsoleReporter } from './reporters/console.js';
import { renderPlatformScan } from './reporters/platform.js';
import { MultiProjectOrchestrator } from './discovery/index.js';
import type { VerimuConfig, Severity, VerimuReport, MultiProjectScanResult } from './core/types.js';
import { GitLabOrchestrator } from './gitlab/orchestrator.js';
import { GitHubOrchestrator } from './github/orchestrator.js';
import { HtmlReporter } from './reporters/html.js';
import type { GitLabScanConfig } from './gitlab/types.js';
import type { GitHubScanConfig, GitHubScanResult, GitHubRepoScanResult, GitHubRepo } from './github/types.js';

// ─── Version & branding ─────────────────────────────────────────

const require = createRequire(import.meta.url);
const pkg = require('../package.json') as { version?: string };
const VERSION = pkg.version ?? '0.0.0';

const BRAND = `
  ╦  ╦┌─┐┬─┐┬┌┬┐┬ ┬
  ╚╗╔╝├┤ ├┬┘│││││ │
   ╚╝ └─┘┴└─┴┴ ┴└─┘
  CRA Compliance Scanner v${VERSION}
`;

function log(msg: string) {
  console.log(`  ${msg}`);
}

function logSuccess(msg: string) {
  console.log(`  ✓ ${msg}`);
}

function logWarn(msg: string) {
  console.log(`  ⚠ ${msg}`);
}

function logError(msg: string) {
  console.error(`  ✗ ${msg}`);
}

// ─── Arg parsing (minimal, no deps) ────────────────────────────

interface CliArgs {
  command: 'scan' | 'generate-sbom' | 'gitlab' | 'github' | 'help' | 'version';
  projectPath: string;
  sbomOutput: string;
  failOnSeverity: Severity | null;
  skipCveCheck: boolean;
  skipUpload: boolean;
  cyclonedxVersion: '1.4' | '1.5' | '1.6' | '1.7';
  contextLines?: number;
  groupName?: string;
  recursive: boolean;  // true by default, use --no-recursive to disable
  // GitLab scanning
  gitlabUrl?: string;
  gitlabToken?: string;
  gitlabGroups?: string[];
  excludeArchived?: boolean;
  excludeForks?: boolean;
  maxRepos?: number;
  htmlOutput?: string;
  jsonOutput?: string;
  exclude?: string[];
  // GitHub scanning
  githubUrl?: string;
  githubToken?: string;
  githubProfile?: string;
  githubOwnerOnly?: boolean;
}

export function parseArgs(argv: string[]): CliArgs {
  const args = argv.slice(2); // strip node + script path
  const result: CliArgs = {
    command: 'scan',
    projectPath: '.',
    sbomOutput: './sbom.cdx.json',
    failOnSeverity: null,
    skipCveCheck: false,
    skipUpload: false,
    cyclonedxVersion: '1.7',
    contextLines: undefined,
    groupName: undefined,
    recursive: true,  // Recursive by default
    gitlabUrl: undefined,
    gitlabToken: undefined,
    gitlabGroups: undefined,
    excludeArchived: true,
    excludeForks: true,
    maxRepos: undefined,
    htmlOutput: undefined,
    jsonOutput: undefined,
    exclude: undefined,
  };

  let i = 0;
  while (i < args.length) {
    const arg = args[i];

    if (arg === 'scan') {
      result.command = 'scan';
    } else if (arg === 'generate-sbom' || arg === 'sbom') {
      result.command = 'generate-sbom';
      result.skipCveCheck = true;
    } else if (arg === 'gitlab') {
      result.command = 'gitlab';
    } else if (arg === 'github') {
      result.command = 'github';
    } else if (arg === '--url') {
      const urlVal = args[++i] ?? '';
      result.gitlabUrl = urlVal;
      result.githubUrl = urlVal;
    } else if (arg === '--token') {
      const tokenVal = args[++i] ?? '';
      result.gitlabToken = tokenVal;
      result.githubToken = tokenVal;
    } else if (arg === '--profile') {
      result.githubProfile = args[++i] ?? '';
    } else if (arg === '--owner-only') {
      result.githubOwnerOnly = true;
    } else if (arg === '--groups') {
      const val = args[++i] ?? '';
      result.gitlabGroups = val.split(',').map(g => g.trim());
    } else if (arg === '--no-archived') {
      result.excludeArchived = true;
    } else if (arg === '--include-archived') {
      result.excludeArchived = false;
    } else if (arg === '--include-forks') {
      result.excludeForks = false;
    } else if (arg === '--max-repos') {
      result.maxRepos = Number.parseInt(args[++i] ?? '0', 10);
    } else if (arg === '--html-output' || arg === '--html') {
      result.htmlOutput = args[++i] ?? './verimu-report.html';
    } else if (arg === '--json-output') {
      result.jsonOutput = args[++i] ?? './verimu-report.json';
    } else if (arg === 'help' || arg === '--help' || arg === '-h') {
      result.command = 'help';
    } else if (arg === 'version' || arg === '--version' || arg === '-v') {
      result.command = 'version';
    } else if (arg === '--path' || arg === '-p') {
      result.projectPath = args[++i] ?? '.';
    } else if (arg === '--output' || arg === '-o') {
      result.sbomOutput = args[++i] ?? './sbom.cdx.json';
    } else if (arg === '--fail-on') {
      const val = (args[++i] ?? '').toUpperCase() as Severity;
      if (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(val)) {
        result.failOnSeverity = val;
      }
    } else if (arg === '--skip-cve') {
      result.skipCveCheck = true;
    } else if (arg === '--skip-upload' || arg === '--offline') {
      result.skipUpload = true;
    } else if (arg === '--context-lines' || arg.startsWith('--context-lines=')) {
      const val = arg === '--context-lines' ? args[++i] : arg.split('=')[1];
      if (!val || val.startsWith('--')) {
        throw new Error('--context-lines requires a numeric value');
      }

      const parsed = Number.parseInt(val, 10);
      if (!Number.isFinite(parsed)) {
        throw new Error(`Invalid --context-lines value: ${val}`);
      }
      result.contextLines = parsed;
    } else if (arg === '--cdx-version' || arg.startsWith('--cdx-version=')) {
      const val =
        arg === '--cdx-version'
          ? args[++i]
          : arg.split('=')[1];
      if (!val || val.startsWith('--')) {
        throw new Error('--cdx-version requires a value');
      }
      if (!['1.4', '1.5', '1.6', '1.7'].includes(val)) {
        throw new Error(`Invalid CycloneDX version: ${val}`);
      }
      result.cyclonedxVersion = val as '1.4' | '1.5' | '1.6' | '1.7';
    } else if (arg === '--group-name' || arg.startsWith('--group-name=')) {
      const val = arg.startsWith('--group-name=')
        ? arg.split('=')[1]
        : args[++i];
      if (!val || val.startsWith('--')) {
        throw new Error('--group-name requires a value');
      }
      result.groupName = val;
    } else if (arg === '--no-recursive' || arg === '--not-recursive') {
      result.recursive = false;
    } else if (arg === '--exclude') {
      const val = args[++i];
      if (!val || val.startsWith('--')) {
        throw new Error('--exclude requires a comma-separated list of patterns');
      }
      result.exclude = val.split(',').map(p => p.trim());
    }

    i++;
  }

  return result;
}

// ─── Main ───────────────────────────────────────────────────────

async function main(): Promise<void> {
  let args: CliArgs;
  try {
    args = parseArgs(process.argv);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    logError(msg);
    log("Run 'npx verimu --help' for usage information");
    process.exit(2);
  }

  if (args.command === 'version') {
    console.log(`verimu ${VERSION}`);
    return;
  }

  if (args.command === 'help') {
    printHelp();
    return;
  }

  // Handle gitlab command
  if (args.command === "gitlab") {
    console.log(BRAND);
    await runGitLabScan(args);
    return;
  }

  // Handle github command
  if (args.command === "github") {
    console.log(BRAND);
    await runGitHubScan(args);
    return;
  }

  console.log(BRAND);

  const apiKey = process.env.VERIMU_API_KEY;
  const apiBaseUrl = process.env.VERIMU_API_URL;

  // Show status
  log(`Scanning ${resolve(args.projectPath)}...`);
  if (apiKey && !args.skipUpload) {
    log('API key detected — results will sync to Verimu platform');
  } else if (!apiKey) {
    log('No VERIMU_API_KEY set — running in offline mode');
    log('Get your API key at https://app.verimu.com/dashboard/api-keys');
  }
  console.log('');

  const config: VerimuConfig = {
    projectPath: resolve(args.projectPath),
    sbomOutput: args.sbomOutput,
    skipCveCheck: args.skipCveCheck,
    cyclonedxVersion: args.cyclonedxVersion,
    // Don't pass apiKey to scan() if --skip-upload — we'll handle upload separately for better logging
    apiKey: (apiKey && !args.skipUpload) ? undefined : undefined,
    apiBaseUrl,
    numContextLines: args.contextLines,
    groupName: args.groupName,
  };

  // Handle recursive mode (default behavior)
  if (args.recursive) {
    const orchestrator = new MultiProjectOrchestrator();

    let result: MultiProjectScanResult;
    try {
      result = await orchestrator.scanAll({
        ...config,
        recursive: true,
        exclude: args.exclude,
        // Pass API key for platform uploads
        apiKey: (apiKey && !args.skipUpload) ? apiKey : undefined,
        apiBaseUrl,
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      logError(msg);
      process.exit(2);
    }

    // Print summary
    printMultiProjectSummary(result);

    // Exit with error if any scans failed
    if (result.failed.length > 0) {
      process.exit(1);
    }

    return;
  }

  // Run single project scan
  let report: VerimuReport;
  try {
    report = await scan(config);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    logError(msg);
    process.exit(2);
  }

  // Print local results
  const reporter = new ConsoleReporter();
  console.log(reporter.report(report));

  // Upload to platform (separate step for better logging)
  if (apiKey && !args.skipUpload) {
    console.log('');
    log('Syncing to Verimu platform...');
    try {
      const uploadConfig: VerimuConfig = {
        ...config,
        apiKey,
        apiBaseUrl,
      };
      const result = await uploadToVerimu(report, uploadConfig);

      if (result.projectCreated) {
        logSuccess(`Project created: ${report.project.path}`);
      }
      logSuccess(`${result.totalDependencies} dependencies tracked`);
      console.log(renderPlatformScan(report.project.path, result));
      logSuccess(`Dashboard: ${result.dashboardUrl}`);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      logWarn(`Platform sync failed: ${msg}`);
      log('Your SBOM was still generated locally. You can upload it manually.');
    }
  }

  // Verimu branding footer
  console.log('');
  log('Thanks for using Verimu — helping your team with CRA readiness');
  console.log('');

  // CI exit code
  if (args.failOnSeverity && shouldFailCi(report, args.failOnSeverity)) {
    logError(`Vulnerabilities found at or above ${args.failOnSeverity} severity`);
    process.exit(1);
  }
}

async function runGitLabScan(args: CliArgs): Promise<void> {
  const url = args.gitlabUrl || process.env.GITLAB_URL || process.env.VERIMU_GITLAB_URL;
  const token = args.gitlabToken || process.env.GITLAB_TOKEN || process.env.VERIMU_GITLAB_TOKEN;

  if (!url) {
    logError('GitLab URL required. Use --url or set GITLAB_URL / VERIMU_GITLAB_URL');
    process.exit(2);
  }

  if (!token) {
    logError('GitLab token required. Use --token or set GITLAB_TOKEN / VERIMU_GITLAB_TOKEN');
    process.exit(2);
  }

  const config: GitLabScanConfig = {
    url,
    token,
    groups: args.gitlabGroups,
    excludeArchived: args.excludeArchived ?? true,
    excludeForks: args.excludeForks ?? true,
    maxRepos: args.maxRepos,
    htmlOutput: args.htmlOutput,
    jsonOutput: args.jsonOutput,
    skipCveCheck: args.skipCveCheck,
    apiKey: process.env.VERIMU_API_KEY,
    apiBaseUrl: process.env.VERIMU_API_URL,
    groupName: args.groupName,
  };

  const orchestrator = new GitLabOrchestrator();
  const result = await orchestrator.scanInstance(config);

  // Write HTML report
  if (args.htmlOutput) {
    const reporter = new HtmlReporter();
    const html = reporter.generate(result);
    const { writeFile: wf } = await import('fs/promises');
    await wf(args.htmlOutput, html, 'utf-8');
    logSuccess('HTML report: ' + args.htmlOutput);
  }

  // Write JSON report
  if (args.jsonOutput) {
    const { writeFile: wf } = await import('fs/promises');
    await wf(args.jsonOutput, JSON.stringify(result, null, 2), 'utf-8');
    logSuccess('JSON report: ' + args.jsonOutput);
  }

  // Exit with error if vulnerabilities found
  if (result.summary.totalVulnerabilities > 0 && args.failOnSeverity) {
    process.exit(1);
  }
}

async function runGitHubScan(args: CliArgs): Promise<void> {
  const baseUrl = args.githubUrl || process.env.GITHUB_URL || 'https://github.com';
  const token = args.githubToken || process.env.GITHUB_TOKEN;
  const profile = args.githubProfile || process.env.GITHUB_PROFILE;

  if (!profile) {
    logError('GitHub profile required. Use --profile <org-or-user> or set GITHUB_PROFILE');
    log('  Example: npx verimu github --profile octokit');
    log('  Example: npx verimu github --profile https://github.com/my-org');
    process.exit(2);
  }

  if (!token) {
    logWarn('No GitHub token provided. Only public repos will be scanned (60 API requests/hour).');
    log('  Use --token or set GITHUB_TOKEN for private repo access (5,000 requests/hour).');
    console.log('');
  }

  const config: GitHubScanConfig = {
    baseUrl,
    profile,
    token: token || undefined,
    ownerOnly: args.githubOwnerOnly ?? false,
    excludeArchived: args.excludeArchived ?? true,
    excludeForks: args.excludeForks ?? true,
    maxRepos: args.maxRepos,
    htmlOutput: args.htmlOutput,
    jsonOutput: args.jsonOutput,
    skipCveCheck: args.skipCveCheck,
    apiKey: process.env.VERIMU_API_KEY,
    apiBaseUrl: process.env.VERIMU_API_URL,
    groupName: args.groupName,
  };

  const orchestrator = new GitHubOrchestrator();
  const result = await orchestrator.scanProfile(config);

  // Write HTML report (reuse existing HtmlReporter by adapting result shape)
  if (args.htmlOutput) {
    const reporter = new HtmlReporter();
    // Adapt GitHub result to the format expected by HtmlReporter
    const adapted = adaptGitHubResultForHtml(result);
    const html = reporter.generate(adapted);
    const { writeFile: wf } = await import('fs/promises');
    await wf(args.htmlOutput, html, 'utf-8');
    logSuccess('HTML report: ' + args.htmlOutput);
  }

  // Write JSON report
  if (args.jsonOutput) {
    const { writeFile: wf } = await import('fs/promises');
    await wf(args.jsonOutput, JSON.stringify(result, null, 2), 'utf-8');
    logSuccess('JSON report: ' + args.jsonOutput);
  }

  // Exit with error if vulnerabilities found
  if (result.summary.totalVulnerabilities > 0 && args.failOnSeverity) {
    process.exit(1);
  }
}

/**
 * Adapts a GitHubScanResult to the GitLabScanResult shape
 * so we can reuse the existing HtmlReporter.
 *
 * The HTML reporter only reads: instanceUrl, summary, topVulnerabilities,
 * scannedRepos, scannedAt, durationMs — all of which are structurally
 * compatible except scannedRepos[].project vs scannedRepos[].repo.
 */
function adaptGitHubResultForHtml(result: GitHubScanResult): import('./gitlab/types.js').GitLabScanResult {
  const toGitLabProject = (repo: GitHubRepo) => ({
    id: repo.id,
    name: repo.name,
    name_with_namespace: repo.full_name,
    path: repo.name,
    path_with_namespace: repo.full_name,
    description: null,
    http_url_to_repo: repo.clone_url,
    ssh_url_to_repo: '',
    web_url: repo.html_url,
    default_branch: repo.default_branch,
    archived: repo.archived,
    empty_repo: false,
    visibility: repo.private ? 'private' as const : 'public' as const,
    last_activity_at: '',
    namespace: {
      id: 0,
      name: repo.owner.login,
      path: repo.owner.login,
      kind: (repo.owner.type === 'Organization' ? 'group' : 'user') as 'group' | 'user',
      full_path: repo.owner.login,
    },
  });

  return {
    instanceUrl: `${result.instanceUrl}/${result.profile}`,
    totalReposDiscovered: result.totalReposDiscovered,
    scannedRepos: result.scannedRepos.map((r: GitHubRepoScanResult) => ({
      project: toGitLabProject(r.repo),
      reports: r.reports,
      hasLockfile: r.hasLockfile,
      error: r.error,
      durationMs: r.durationMs,
    })),
    skippedRepos: result.skippedRepos.map((s: { repo: GitHubRepo; reason: string }) => ({
      project: toGitLabProject(s.repo),
      reason: s.reason,
    })),
    failedRepos: result.failedRepos.map((f: { repo: GitHubRepo; error: string }) => ({
      project: toGitLabProject(f.repo),
      error: f.error,
    })),
    summary: result.summary,
    topVulnerabilities: result.topVulnerabilities,
    scannedAt: result.scannedAt,
    durationMs: result.durationMs,
  };
}

function printMultiProjectSummary(result: MultiProjectScanResult): void {
  console.log('\n' + '─'.repeat(60));
  console.log('Multi-Project Scan Summary');
  console.log('─'.repeat(60));

  console.log(`\nProjects discovered: ${result.totalDiscovered}`);
  console.log(`  ✓ Successful: ${result.successful.length}`);
  console.log(`  ✗ Failed: ${result.failed.length}`);

  if (result.successful.length > 0) {
    const totalDeps = result.successful.reduce(
      (sum, r) => sum + r.report.summary.totalDependencies,
      0
    );
    const totalVulns = result.successful.reduce(
      (sum, r) => sum + r.report.summary.totalVulnerabilities,
      0
    );

    console.log(`\nTotal dependencies: ${totalDeps}`);
    console.log(`Total vulnerabilities: ${totalVulns}`);

    // Breakdown by severity
    const critical = result.successful.reduce((sum, r) => sum + r.report.summary.critical, 0);
    const high = result.successful.reduce((sum, r) => sum + r.report.summary.high, 0);
    const medium = result.successful.reduce((sum, r) => sum + r.report.summary.medium, 0);
    const low = result.successful.reduce((sum, r) => sum + r.report.summary.low, 0);

    if (totalVulns > 0) {
      console.log(`  Critical: ${critical}, High: ${high}, Medium: ${medium}, Low: ${low}`);
    }
  }

  if (result.failed.length > 0) {
    console.log('\nFailed projects:');
    for (const f of result.failed) {
      console.log(`  • ${f.project.relativePath}: ${f.error}`);
    }
  }

  console.log(`\nCompleted in ${(result.durationMs / 1000).toFixed(2)}s`);
  console.log('');
}

function printHelp(): void {
  console.log(`
  Verimu — CRA Compliance Scanner

  Usage:
    verimu                          Scan current directory (recursively)
    verimu scan [options]           Full scan (SBOM + CVE check)
    verimu generate-sbom [options]  Generate SBOM only (no CVE check)
    verimu help                     Show this help
    verimu version                  Show version

  GitLab scanning:
    verimu gitlab [options]       Scan all repos on a GitLab instance

  GitLab options:
    --url <url>            GitLab instance URL (or GITLAB_URL env)
    --token <token>        Personal access token (or GITLAB_TOKEN env)
    --groups <g1,g2>       Only scan repos in these groups
    --include-archived     Include archived repos (excluded by default)
    --include-forks        Include forked repos (excluded by default)
    --max-repos <n>        Limit number of repos to scan
    --html-output <file>   Write HTML report (e.g., ./report.html)
    --json-output <file>   Write JSON aggregate report

  GitHub scanning:
    verimu github [options]       Scan repos for a GitHub org or user

  GitHub options:
    --profile <handle|url> GitHub org/user to scan (required)
    --url <url>            GitHub base URL (default: https://github.com, for GHES)
    --token <token>        GitHub PAT (or GITHUB_TOKEN env). Without token: public
                           repos only, 60 API requests/hour. With token: private +
                           public repos, 5,000 requests/hour.
    --owner-only           For user profiles, list only owner repos (default: all)
    --include-archived     Include archived repos (excluded by default)
    --include-forks        Include forked repos (excluded by default)
    --max-repos <n>        Limit number of repos to scan
    --html-output <file>   Write HTML report
    --json-output <file>   Write JSON aggregate report
    --skip-cve             Skip CVE vulnerability checking
    --group-name <name>    Group name for Verimu platform

  Options:
    --path, -p <dir>       Project directory to scan (default: .)
    --output, -o <file>    CycloneDX output path (SPDX/SWID are written alongside it)
    --group-name <name>    Group name for organizing related projects in dashboard
    --fail-on <severity>   Exit 1 if vulns at or above: CRITICAL, HIGH, MEDIUM, LOW
    --skip-cve             Skip CVE vulnerability checking
    --skip-upload          Don't sync to Verimu platform (even if API key is set)
    --context-lines <n>    Snippet context lines around matches (default: 4, clamped to 0..20)
    --cdx-version <ver>    CycloneDX spec: 1.4, 1.5, 1.6, 1.7 (default: 1.7)

  Project Discovery:
    --no-recursive         Disable recursive discovery (scan only root directory)
    --exclude <patterns>   Exclude paths matching patterns (comma-separated globs)

  Note: Verimu automatically discovers all projects recursively by default.
  For monorepos with multiple lockfiles, projects are auto-grouped by directory name.
  Single lockfile projects are treated normally without grouping.

  Environment:
    VERIMU_API_KEY         API key for Verimu platform (from app.verimu.com)
    VERIMU_API_URL         Custom API URL (default: https://api.verimu.com)
    GITHUB_TOKEN           GitHub personal access token
    GITHUB_URL             GitHub base URL for GHES (default: https://github.com)

  Examples:
    npx verimu                                    # Scan all projects recursively
    VERIMU_API_KEY=vmu_xxx npx verimu             # Scan + sync to platform
    npx verimu scan --fail-on HIGH                # Fail CI on HIGH+ vulns
    npx verimu scan --group-name my-app           # Group projects with custom name
    npx verimu scan --context-lines 8             # Wider context around usage snippets
    npx verimu scan --cdx-version 1.5             # Specify CycloneDX version
    npx verimu scan --path ./backend --output ./reports/sbom.json
    npx verimu scan --no-recursive                # Scan only root directory
    npx verimu scan --exclude "legacy/*"          # Exclude legacy projects

  GitLab examples:
    GITLAB_TOKEN=xxx npx verimu gitlab --url https://git.example.com --html report.html
    npx verimu gitlab --url https://git.example.com --token xxx --groups myteam
    npx verimu gitlab --url https://git.example.com --token xxx --max-repos 5

  GitHub examples:
    npx verimu github --profile octokit --max-repos 5 --json-output report.json
    npx verimu github --profile Saksham0170 --owner-only
    GITHUB_TOKEN=ghp_xxx npx verimu github --profile my-org --html-output report.html
    npx verimu github --profile https://github.com/my-org --token ghp_xxx
    npx verimu github --url https://github.company.com --profile team --token xxx

  Supported ecosystems:
    npm (package-lock.json)         pip (requirements.txt)
    Maven (pom.xml)                 NuGet (packages.lock.json)
    Cargo (Cargo.lock)              Go (go.sum)
    Ruby (Gemfile.lock)             Composer (composer.lock)

  Learn more: https://verimu.com
  Dashboard: https://app.verimu.com
`);
}
main().catch((err) => {
  console.error('Fatal:', err);
  process.exit(2);
});
