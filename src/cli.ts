

/**
 * Verimu CLI — CRA compliance scanner.
 *
 * Usage:
 *   npx verimu                        # scan current directory
 *   npx verimu scan                   # explicit scan command
 *   npx verimu scan --path ./myapp    # scan specific directory
 *   npx verimu generate-sbom          # SBOM only, no CVE check
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
import type { VerimuConfig, Severity, VerimuReport } from './core/types.js';
import type { UploadResult } from './scan.js';

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

function renderPlatformScan(projectPath: string, result: UploadResult): string {
  const lines: string[] = [];
  const vulns = result.scanResponse.scan_results.flatMap((scanResult) =>
    scanResult.vulnerabilities.map((vuln) => ({
      dependencyName: scanResult.dependency_name,
      version: scanResult.version,
      cveId: vuln.cve_id,
      severity: normalizeSeverity(vuln.severity),
      summary: vuln.summary,
      fixedVersion: vuln.fixed_version,
    }))
  );

  const summary = summarizeBySeverity(vulns.map((vuln) => vuln.severity));

  lines.push('');
  lines.push('┌─────────────────────────────────────────────┐');
  lines.push('│         VERIMU PLATFORM SCAN RESULTS        │');
  lines.push('└─────────────────────────────────────────────┘');
  lines.push('');
  lines.push(`  Project:      ${projectPath}`);
  lines.push('  Source:       Verimu platform backend');
  lines.push(`  Dependencies: ${result.totalDependencies}`);
  lines.push('');

  if (vulns.length === 0) {
    lines.push('  ✓ No platform vulnerabilities found');
  } else {
    lines.push(`  ⚠ ${vulns.length} backend vulnerabilit${vulns.length === 1 ? 'y' : 'ies'} found:`);
    lines.push('');

    const sorted = [...vulns].sort((a, b) => severityOrder(a.severity) - severityOrder(b.severity));
    for (const vuln of sorted) {
      const fix = vuln.fixedVersion ? ` → fix: ${vuln.fixedVersion}` : '';
      lines.push(`    ${severityBadge(vuln.severity)}  ${vuln.cveId}`);
      lines.push(`           ${vuln.dependencyName}@${vuln.version}${fix}`);
      lines.push(`           ${vuln.summary.slice(0, 100)}`);
      lines.push('');
    }
  }

  lines.push('  ─── Summary ───');
  lines.push(`  Total: ${vulns.length}  |  ` +
    `Critical: ${summary.CRITICAL}  |  ` +
    `High: ${summary.HIGH}  |  ` +
    `Medium: ${summary.MEDIUM}  |  ` +
    `Low: ${summary.LOW}`);
  lines.push('');

  return lines.join('\n');
}

function normalizeSeverity(severity: string): Severity {
  const value = severity.trim().toUpperCase();
  switch (value) {
    case 'CRITICAL':
    case 'HIGH':
    case 'MEDIUM':
    case 'LOW':
      return value;
    default:
      return 'UNKNOWN';
  }
}

function summarizeBySeverity(severities: Severity[]): Record<Severity, number> {
  const summary: Record<Severity, number> = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    UNKNOWN: 0,
  };

  for (const severity of severities) {
    summary[severity] += 1;
  }

  return summary;
}

function severityOrder(severity: Severity): number {
  const order: Record<Severity, number> = {
    CRITICAL: 0,
    HIGH: 1,
    MEDIUM: 2,
    LOW: 3,
    UNKNOWN: 4,
  };
  return order[severity] ?? 5;
}

function severityBadge(severity: Severity): string {
  const badges: Record<Severity, string> = {
    CRITICAL: '[CRIT]',
    HIGH: '[HIGH]',
    MEDIUM: '[MED] ',
    LOW: '[LOW] ',
    UNKNOWN: '[???] ',
  };
  return badges[severity] ?? '[???] ';
}

// ─── Arg parsing (minimal, no deps) ────────────────────────────

interface CliArgs {
  command: 'scan' | 'generate-sbom' | 'help' | 'version';
  projectPath: string;
  sbomOutput: string;
  failOnSeverity: Severity | null;
  skipCveCheck: boolean;
  skipUpload: boolean;
}

function parseArgs(argv: string[]): CliArgs {
  const args = argv.slice(2); // strip node + script path
  const result: CliArgs = {
    command: 'scan',
    projectPath: '.',
    sbomOutput: './sbom.cdx.json',
    failOnSeverity: null,
    skipCveCheck: false,
    skipUpload: false,
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
    }

    i++;
  }

  return result;
}

// ─── Main ───────────────────────────────────────────────────────

async function main(): Promise<void> {
  const args = parseArgs(process.argv);

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
    // Don't pass apiKey to scan() if --skip-upload — we'll handle upload separately for better logging
    apiKey: (apiKey && !args.skipUpload) ? undefined : undefined,
    apiBaseUrl,
  };

  // Run scan
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
  log('Thanks for using Verimu — keeping your software CRA-compliant 🛡️');
  console.log('');

  // CI exit code
  if (args.failOnSeverity && shouldFailCi(report, args.failOnSeverity)) {
    logError(`Vulnerabilities found at or above ${args.failOnSeverity} severity`);
    process.exit(1);
  }
}

function printHelp(): void {
  console.log(`
  Verimu — CRA Compliance Scanner

  Usage:
    verimu                          Scan current directory
    verimu scan [options]           Full scan (SBOM + CVE check)
    verimu generate-sbom [options]  Generate SBOM only (no CVE check)
    verimu help                     Show this help
    verimu version                  Show version

  Options:
    --path, -p <dir>       Project directory to scan (default: .)
    --output, -o <file>    SBOM output path (default: ./sbom.cdx.json)
    --fail-on <severity>   Exit 1 if vulns at or above: CRITICAL, HIGH, MEDIUM, LOW
    --skip-cve             Skip CVE vulnerability checking
    --skip-upload          Don't sync to Verimu platform (even if API key is set)

  Environment:
    VERIMU_API_KEY         API key for Verimu platform (from app.verimu.com)
    VERIMU_API_URL         Custom API URL (default: https://api.verimu.com)

  Examples:
    npx verimu                                    # Quick scan
    VERIMU_API_KEY=vmu_xxx npx verimu             # Scan + sync to platform
    npx verimu scan --fail-on HIGH                # Fail CI on HIGH+ vulns
    npx verimu scan --path ./backend --output ./reports/sbom.json

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
