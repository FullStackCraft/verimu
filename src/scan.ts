import { writeFile } from 'fs/promises';
import { basename } from 'path';
import { ScannerRegistry } from './scanners/registry.js';
import { CycloneDxGenerator } from './sbom/cyclonedx.js';
import { CveAggregator } from './cve/aggregator.js';
import { ConsoleReporter } from './reporters/console.js';
import { VerimuApiClient } from './api/client.js';
import type { VerimuConfig, VerimuReport, Severity } from './core/types.js';

/** Result of uploading scan results to the Verimu platform */
export interface UploadResult {
  projectId: string;
  projectCreated: boolean;
  totalDependencies: number;
  vulnerableDependencies: number;
  dashboardUrl: string;
}

/**
 * Main scan pipeline — orchestrates the full Verimu workflow:
 *   1. Detect ecosystem & parse lockfile
 *   2. Generate CycloneDX SBOM
 *   3. Check dependencies for CVEs (via OSV)
 *   4. Produce report
 *   5. Upload to Verimu platform (if API key provided)
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

  // 6. Upload to Verimu platform (if API key provided)
  if (config.apiKey) {
    try {
      const uploadResult = await uploadToVerimu(report, config);
      (report as VerimuReport & { upload?: UploadResult }).upload = uploadResult;
    } catch {
      // Upload failure should not break the scan — log but continue
      // The CLI will handle displaying the error
    }
  }

  return report;
}

/**
 * Uploads scan results to the Verimu platform.
 *
 * 1. Upserts the project (create-if-not-exists by name)
 * 2. POSTs the SBOM for dependency tracking + CVE scanning
 */
export async function uploadToVerimu(
  report: VerimuReport,
  config: VerimuConfig
): Promise<UploadResult> {
  if (!config.apiKey) {
    throw new Error('API key required for upload');
  }

  const client = new VerimuApiClient(config.apiKey, config.apiBaseUrl);

  // Derive project name from the directory
  const projectName = basename(config.projectPath);

  // 1. Upsert project
  const upsertRes = await client.upsertProject({
    name: projectName,
    ecosystem: report.project.ecosystem,
  });

  const projectId = upsertRes.project.id;

  // 2. Upload SBOM
  const scanRes = await client.uploadSbom(projectId, report.sbom.content);

  return {
    projectId,
    projectCreated: upsertRes.created,
    totalDependencies: scanRes.summary.total_dependencies,
    vulnerableDependencies: scanRes.summary.vulnerable_dependencies,
    dashboardUrl: `https://app.verimu.com/dashboard/projects/${projectId}`,
  };
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
