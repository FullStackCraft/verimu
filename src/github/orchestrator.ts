/**
 * GitHub scan orchestrator — clones each repo, scans with Verimu,
 * aggregates results, and generates the report.
 *
 *
 * Usage:
 *   const orchestrator = new GitHubOrchestrator();
 *   const result = await orchestrator.scanProfile(config);
 */

import { GitHubClient, parseProfile } from './client.js';
import { scan } from '../scan.js';
import { LockfileDiscovery } from '../discovery/lockfile-discovery.js';
import type {
  GitHubScanConfig,
  GitHubScanResult,
  GitHubRepoScanResult,
  GitHubRepo,
} from './types.js';
import type { VerimuReport, Severity } from '../core/types.js';

export class GitHubOrchestrator {
  private discovery = new LockfileDiscovery();

  /**
   * Scans all repos for a GitHub profile (org or user).
   */
  async scanProfile(config: GitHubScanConfig): Promise<GitHubScanResult> {
    const startTime = Date.now();
    const client = new GitHubClient(config.baseUrl, config.token);

    // 1. Parse profile
    const { login } = parseProfile(config.profile, config.baseUrl);
    console.log(`\n  GitHub profile: ${login}`);
    console.log(`  Base URL: ${config.baseUrl}`);
    console.log(`  Auth: ${config.token ? 'token provided (5,000 req/h)' : 'unauthenticated (60 req/h)'}`);

    // 2. Detect owner type via API
    process.stdout.write('  Detecting profile type... ');
    const ownerType = await client.detectOwnerType(login);
    console.log(ownerType);

    // 3. List repos
    console.log('  Listing repositories...');
    const repos = await client.listRepos(login, ownerType, {
      ownerOnly: config.ownerOnly ?? false,
    });
    console.log(`  Found ${repos.length} repositories\n`);

    // 4. Filter
    const { toScan, skipped } = this.filterRepos(repos, config);
    console.log(`  Scanning ${toScan.length} repos (${skipped.length} skipped)\n`);

    // 5. Clone → Discover → Scan → Cleanup each repo
    const scannedRepos: GitHubRepoScanResult[] = [];
    const failedRepos: Array<{ repo: GitHubRepo; error: string }> = [];

    for (let i = 0; i < toScan.length; i++) {
      const repo = toScan[i];
      const label = `[${i + 1}/${toScan.length}]`;

      console.log(`  ${label} ${repo.full_name}`);

      const repoStart = Date.now();
      let tempDir: string | null = null;

      try {
        // Clone
        process.stdout.write('    Cloning... ');
        tempDir = client.cloneToTemp(repo, config.branch);
        console.log('done');

        // Discover lockfiles recursively within the cloned repo
        const discovered = await this.discovery.discover({
          rootPath: tempDir,
        });

        if (discovered.length === 0) {
          console.log('    no lockfile found');
          scannedRepos.push({
            repo,
            reports: [],
            hasLockfile: false,
            durationMs: Date.now() - repoStart,
          });
          continue;
        }

        console.log(`    Found ${discovered.length} project(s)`);

        // Scan each discovered project within the repo
        const reports: VerimuReport[] = [];

        for (const disc of discovered) {
          const subLabel = discovered.length > 1
            ? ` (${disc.relativePath})`
            : '';

          const uploadProjectName = discovered.length > 1 && disc.relativePath !== '.'
            ? `${repo.full_name}/${disc.relativePath}`
            : repo.full_name;
          const safeArtifactSuffix = uploadProjectName
            .replace(/[\\/:*?"<>|]/g, '-')
            .replace(/\s+/g, '-')
            .toLowerCase();
          const sbomOutput = `${tempDir}/sbom.${safeArtifactSuffix}.cdx.json`;

          process.stdout.write(`    Scanning${subLabel}... `);

          try {
            const report = await scan({
              projectPath: disc.projectPath,
              sbomOutput,
              skipCveCheck: config.skipCveCheck ?? false,
              apiKey: config.apiKey,
              apiBaseUrl: config.apiBaseUrl,
              groupName: config.groupName,
              uploadProjectName,
              repositoryUrl: repo.html_url,
              platform: 'github',
            });

            const vulnCount = report.summary.totalVulnerabilities;
            const depCount = report.summary.totalDependencies;
            if (vulnCount > 0) {
              console.log(
                `${depCount} deps, ${vulnCount} vulns ` +
                `(C:${report.summary.critical} H:${report.summary.high} ` +
                `M:${report.summary.medium} L:${report.summary.low})`
              );
            } else {
              console.log(`${depCount} deps, clean`);
            }

            reports.push(report);
          } catch (scanErr: unknown) {
            const msg = scanErr instanceof Error ? scanErr.message : String(scanErr);
            console.log(`FAILED: ${msg.slice(0, 80)}`);
          }
        }

        const durationMs = Date.now() - repoStart;

        scannedRepos.push({
          repo,
          reports,
          hasLockfile: true,
          durationMs,
        });
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        const durationMs = Date.now() - repoStart;

        if (msg.includes('No supported lockfile') || msg.includes('NoLockfileError')) {
          console.log('    no lockfile found');
          scannedRepos.push({
            repo,
            reports: [],
            hasLockfile: false,
            durationMs,
          });
        } else {
          console.log(`    FAILED: ${msg.slice(0, 100)}`);
          failedRepos.push({ repo, error: msg });
        }
      } finally {
        // Always cleanup
        if (tempDir) {
          client.cleanupTemp(tempDir);
        }
      }

      console.log('');
    }

    // 6. Aggregate results
    const result = this.aggregate(
      config.baseUrl,
      login,
      ownerType,
      repos.length,
      scannedRepos,
      skipped,
      failedRepos,
      Date.now() - startTime
    );

    // 7. Print summary
    this.printSummary(result);

    return result;
  }

  // ─── Filtering ──────────────────────────────────────────────

  private filterRepos(
    repos: GitHubRepo[],
    config: GitHubScanConfig
  ): {
    toScan: GitHubRepo[];
    skipped: Array<{ repo: GitHubRepo; reason: string }>;
  } {
    const toScan: GitHubRepo[] = [];
    const skipped: Array<{ repo: GitHubRepo; reason: string }> = [];

    for (const repo of repos) {
      // Archived
      if (config.excludeArchived !== false && repo.archived) {
        skipped.push({ repo, reason: 'archived' });
        continue;
      }

      // Forks
      if (config.excludeForks && repo.fork) {
        skipped.push({ repo, reason: 'fork' });
        continue;
      }

      toScan.push(repo);
    }

    // Apply max repos limit
    if (config.maxRepos && toScan.length > config.maxRepos) {
      const trimmed = toScan.splice(config.maxRepos);
      for (const r of trimmed) {
        skipped.push({ repo: r, reason: 'exceeded --max-repos limit' });
      }
    }

    return { toScan, skipped };
  }

  // ─── Aggregation ────────────────────────────────────────────

  private aggregate(
    instanceUrl: string,
    profile: string,
    profileType: 'org' | 'user',
    totalDiscovered: number,
    scannedRepos: GitHubRepoScanResult[],
    skippedRepos: Array<{ repo: GitHubRepo; reason: string }>,
    failedRepos: Array<{ repo: GitHubRepo; error: string }>,
    durationMs: number
  ): GitHubScanResult {
    // Flatten: each repo may have multiple reports
    const reposWithData = scannedRepos.filter((r) => r.reports.length > 0);

    // Aggregate summary
    const ecosystemBreakdown: Record<string, number> = {};
    let totalDeps = 0;
    let totalVulns = 0;
    let critical = 0;
    let high = 0;
    let medium = 0;
    let low = 0;
    let exploitedInWild = 0;
    let reposWithVulns = 0;

    for (const { reports } of reposWithData) {
      let repoHasVulns = false;

      for (const report of reports) {
        totalDeps += report.summary.totalDependencies;
        totalVulns += report.summary.totalVulnerabilities;
        critical += report.summary.critical;
        high += report.summary.high;
        medium += report.summary.medium;
        low += report.summary.low;
        exploitedInWild += report.summary.exploitedInWild;

        if (report.summary.totalVulnerabilities > 0) {
          repoHasVulns = true;
        }

        const eco = report.project.ecosystem;
        ecosystemBreakdown[eco] = (ecosystemBreakdown[eco] ?? 0) + 1;
      }

      if (repoHasVulns) reposWithVulns++;
    }

    // Dedupe top vulnerabilities across repos
    const vulnMap = new Map<string, {
      id: string;
      severity: Severity;
      summary: string;
      affectedRepos: string[];
      fixedVersion?: string;
      exploitedInWild: boolean;
    }>();

    for (const { repo, reports } of reposWithData) {
      for (const report of reports) {
        for (const vuln of report.cveCheck.vulnerabilities) {
          const existing = vulnMap.get(vuln.id);
          if (existing) {
            if (!existing.affectedRepos.includes(repo.full_name)) {
              existing.affectedRepos.push(repo.full_name);
            }
          } else {
            vulnMap.set(vuln.id, {
              id: vuln.id,
              severity: vuln.severity,
              summary: vuln.summary,
              affectedRepos: [repo.full_name],
              fixedVersion: vuln.fixedVersion,
              exploitedInWild: vuln.exploitedInWild,
            });
          }
        }
      }
    }

    const severityOrder: Record<Severity, number> = {
      CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNKNOWN: 4,
    };

    const topVulnerabilities = Array.from(vulnMap.values())
      .sort((a, b) => {
        const sevDiff = severityOrder[a.severity] - severityOrder[b.severity];
        if (sevDiff !== 0) return sevDiff;
        return b.affectedRepos.length - a.affectedRepos.length;
      });

    return {
      instanceUrl,
      profile,
      profileType,
      totalReposDiscovered: totalDiscovered,
      scannedRepos,
      skippedRepos,
      failedRepos,
      summary: {
        totalRepos: reposWithData.length,
        reposWithVulnerabilities: reposWithVulns,
        totalDependencies: totalDeps,
        totalVulnerabilities: totalVulns,
        critical,
        high,
        medium,
        low,
        exploitedInWild,
        ecosystemBreakdown,
      },
      topVulnerabilities,
      scannedAt: new Date().toISOString(),
      durationMs,
    };
  }

  // ─── Summary Printing ───────────────────────────────────────

  private printSummary(result: GitHubScanResult): void {
    const noLockfile = result.scannedRepos.filter((r) => !r.hasLockfile).length;
    const withLockfile = result.scannedRepos.filter((r) => r.hasLockfile).length;

    console.log('\n' + '═'.repeat(60));
    console.log('  VERIMU GITHUB SCAN — COMPLETE');
    console.log('═'.repeat(60));
    console.log(`\n  Profile:      ${result.profile} (${result.profileType})`);
    console.log(`  Instance:     ${result.instanceUrl}`);
    console.log('');
    console.log(`  Repos found:      ${result.totalReposDiscovered}`);
    console.log(`    With lockfile:  ${withLockfile}`);
    console.log(`    No lockfile:    ${noLockfile}`);
    console.log(`    Skipped:        ${result.skippedRepos.length}  (archived/fork/limit)`);
    console.log(`    Failed:         ${result.failedRepos.length}  (clone/scan error)`);
    console.log('');
    console.log(`  Repos with vulns: ${result.summary.reposWithVulnerabilities} / ${withLockfile}`);
    console.log('');
    console.log(`  Total dependencies:     ${result.summary.totalDependencies}`);
    console.log(`  Total vulnerabilities:  ${result.summary.totalVulnerabilities}`);
    console.log(`    Critical: ${result.summary.critical}`);
    console.log(`    High:     ${result.summary.high}`);
    console.log(`    Medium:   ${result.summary.medium}`);
    console.log(`    Low:      ${result.summary.low}`);

    if (result.summary.exploitedInWild > 0) {
      console.log(`\n  🔴 ${result.summary.exploitedInWild} actively exploited — CRA 24h reporting required`);
    }

    if (Object.keys(result.summary.ecosystemBreakdown).length > 0) {
      console.log('\n  Ecosystems:');
      for (const [eco, count] of Object.entries(result.summary.ecosystemBreakdown)) {
        console.log(`    ${eco}: ${count} project(s)`);
      }
    }

    console.log(`\n  Completed in ${(result.durationMs / 1000).toFixed(1)}s`);
    console.log('');
  }
}
