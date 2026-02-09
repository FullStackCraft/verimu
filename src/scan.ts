import { writeFile } from 'fs/promises';
import { ScannerRegistry } from './scanners/registry.js';
import { CycloneDxGenerator } from './sbom/cyclonedx.js';
import { CveAggregator } from './cve/aggregator.js';
import { ConsoleReporter } from './reporters/console.js';
import type { VerimuConfig, VerimuReport, Severity } from './core/types.js';

/**
 * Main scan pipeline — orchestrates the full Verimu workflow:
 *   1. Detect ecosystem & parse lockfile
 *   2. Generate CycloneDX SBOM
 *   3. Check dependencies for CVEs
 *   4. Produce report
 *   5. Optionally upload snapshot to Verimu API
 */
export async function scan(config: VerimuConfig): Promise<VerimuReport> {
  const {
    projectPath,
    sbomOutput = './sbom.cdx.json',
    skipCveCheck = false,
  } = config;

  // 1. Scan dependencies
  const registry = new ScannerRegistry();
  const scanResult = await registry.detectAndScan(projectPath);

  // 2. Generate SBOM
  const sbomGenerator = new CycloneDxGenerator();
  const sbom = sbomGenerator.generate(scanResult);

  // 3. Write SBOM to disk
  await writeFile(sbomOutput, sbom.content, 'utf-8');

  // 4. Check CVEs (unless skipped)
  let cveCheck;
  if (skipCveCheck) {
    cveCheck = {
      vulnerabilities: [],
      sourcesQueried: [],
      sourceErrors: [],
      checkDurationMs: 0,
    };
  } else {
    const aggregator = new CveAggregator();
    cveCheck = await aggregator.check(scanResult.dependencies);
  }

  // 5. Build report
  const summary = {
    totalDependencies: scanResult.dependencies.length,
    totalVulnerabilities: cveCheck.vulnerabilities.length,
    critical: cveCheck.vulnerabilities.filter((v) => v.severity === 'CRITICAL').length,
    high: cveCheck.vulnerabilities.filter((v) => v.severity === 'HIGH').length,
    medium: cveCheck.vulnerabilities.filter((v) => v.severity === 'MEDIUM').length,
    low: cveCheck.vulnerabilities.filter((v) => v.severity === 'LOW').length,
    exploitedInWild: cveCheck.vulnerabilities.filter((v) => v.exploitedInWild).length,
  };

  const report: VerimuReport = {
    project: {
      path: projectPath,
      ecosystem: scanResult.ecosystem,
      dependencyCount: scanResult.dependencies.length,
    },
    sbom,
    cveCheck,
    summary,
    generatedAt: new Date().toISOString(),
  };

  return report;
}

/**
 * Determines if the scan should fail CI based on severity threshold.
 */
export function shouldFailCi(report: VerimuReport, threshold: Severity): boolean {
  const severityOrder: Record<Severity, number> = {
    CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNKNOWN: 4,
  };
  const thresholdLevel = severityOrder[threshold] ?? 4;

  return report.cveCheck.vulnerabilities.some(
    (v) => severityOrder[v.severity] <= thresholdLevel
  );
}

/**
 * Prints a console report to stdout.
 */
export function printReport(report: VerimuReport): void {
  const reporter = new ConsoleReporter();
  console.log(reporter.report(report));
}
