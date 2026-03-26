

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
import { createRequire } from 'module';
import { scan, shouldFailCi, uploadToVerimu } from './scan.js';
import { ConsoleReporter } from './reporters/console.js';
import { renderPlatformScan } from './reporters/platform.js';
import { MultiProjectOrchestrator } from './discovery/index.js';
import type { VerimuConfig, Severity, VerimuReport, MultiProjectScanResult } from './core/types.js';

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
  command: 'scan' | 'generate-sbom' | 'help' | 'version';
  projectPath: string;
  sbomOutput: string;
  failOnSeverity: Severity | null;
  skipCveCheck: boolean;
  skipUpload: boolean;
  cyclonedxVersion: '1.4' | '1.5' | '1.6' | '1.7';
  contextLines?: number;
  groupName?: string;
  recursive: boolean;  // true by default, use --no-recursive to disable
  exclude?: string[];
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
