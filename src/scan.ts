import { writeFile } from 'fs/promises';
import { basename, join, parse } from 'path';
import { ScannerRegistry } from './scanners/registry.js';
import { generateSbomArtifacts } from './sbom/artifacts.js';
import { CveAggregator } from './cve/aggregator.js';
import { ConsoleReporter } from './reporters/console.js';
import { VerimuApiClient } from './api/client.js';
import { detectSource } from './core/source.js';
import { UsageContextEngine } from './context/usage-context-engine.js';
import { normalizeNumContextLines } from './context/snippet-extractor.js';
import type { ScanResponse, SbomUploadBundle } from './api/client.js';
import type { UsageContextResult, VerimuConfig, VerimuReport, Severity } from './core/types.js';

/** Result of uploading scan results to the Verimu platform */
export interface UploadResult {
  projectId: string;
  projectCreated: boolean;
  totalDependencies: number;
  vulnerableDependencies: number;
  dashboardUrl: string;
  scanResponse: ScanResponse;
}

/**
 * Main scan pipeline — orchestrates the full Verimu workflow:
 *   1. Detect ecosystem & parse lockfile
 *   2. Generate software inventory artifacts (CycloneDX + SPDX + SWID)
 *   3. Check dependencies for CVEs (via OSV)
 *   4. Produce report
 *   5. Upload to Verimu platform (if API key provided)
 */
export async function scan(config: VerimuConfig): Promise<VerimuReport> {
  const {
    projectPath,
    sbomOutput = './sbom.cdx.json',
    skipCveCheck = false,
    cyclonedxVersion = '1.7',
  } = config;

  // 1. Scan dependencies
  const registry = new ScannerRegistry();
  const scanResult = await registry.detectAndScan(projectPath);

  // 2. Generate all supported artifacts
  const artifacts = generateSbomArtifacts(scanResult, undefined, cyclonedxVersion);
  const sbom = artifacts.cyclonedx;

  // 3. Write artifacts to disk
  const outputPaths = deriveArtifactOutputPaths(sbomOutput);
  await Promise.all([
    writeFile(outputPaths.cyclonedx, artifacts.cyclonedx.content, 'utf-8'),
    writeFile(outputPaths.spdx, artifacts.spdx.content, 'utf-8'),
    writeFile(outputPaths.swid, artifacts.swid.content, 'utf-8'),
  ]);

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

  // 4.5. Analyze vulnerable package usage context (only when CVEs are present)
  let usageContext: VerimuReport['usageContext'];
  if (cveCheck.vulnerabilities.length > 0) {
    const engine = new UsageContextEngine();

    try {
      usageContext = await engine.analyze({
        projectPath,
        dependencies: scanResult.dependencies,
        vulnerabilities: cveCheck.vulnerabilities,
        numContextLines: config.numContextLines,
      });
    } catch (err: unknown) {
      usageContext = {
        triggered: true,
        durationMs: 0,
        numContextLines: normalizeNumContextLines(config.numContextLines),
        maxSnippetsPerPackage: 20,
        maxSnippetsTotal: 500,
        totalSnippets: 0,
        packageFindings: [],
        ecosystemStatus: [],
        errors: [{
          analyzer: 'usage-context-engine',
          error: err instanceof Error ? err.message : String(err),
        }],
        llmPayload: [],
      };
    }

    usageContext.artifactPath = outputPaths.usageContext;
    await writeFile(outputPaths.usageContext, JSON.stringify(usageContext, null, 2), 'utf-8');
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
    artifacts,
    cveCheck,
    usageContext,
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
 * 2. POSTs the artifact bundle for dependency tracking + CVE scanning
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

  // 2. Upload software inventory artifacts
  const scanRes = await client.uploadSbom(projectId, buildUploadPayload(report));

  return {
    projectId,
    projectCreated: upsertRes.created,
    totalDependencies: scanRes.summary.total_dependencies,
    vulnerableDependencies: scanRes.summary.vulnerable_dependencies,
    dashboardUrl: `https://app.verimu.com/dashboard/projects/${projectId}`,
    scanResponse: scanRes,
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

function deriveArtifactOutputPaths(cycloneDxOutput: string): {
  cyclonedx: string;
  spdx: string;
  swid: string;
  usageContext: string;
} {
  const parsed = parse(cycloneDxOutput);
  let baseName = parsed.name;

  if (parsed.ext === '.json' && baseName.endsWith('.cdx')) {
    baseName = baseName.slice(0, -4);
  }

  return {
    cyclonedx: cycloneDxOutput,
    spdx: join(parsed.dir, `${baseName}.spdx.json`),
    swid: join(parsed.dir, `${baseName}.swid.xml`),
    usageContext: join(parsed.dir, `${baseName}.usage-context.json`),
  };
}

function buildUploadPayload(report: VerimuReport): string | SbomUploadBundle {
  const source = detectSource();

  if (!report.artifacts) {
    return report.sbom.content;
  }

  const usageContext = sanitizeUsageContextForUpload(report.usageContext);

  return {
    cyclonedx: JSON.parse(report.artifacts.cyclonedx.content) as Record<string, unknown>,
    spdx: JSON.parse(report.artifacts.spdx.content) as Record<string, unknown>,
    swid: report.artifacts.swid.content,
    usage_context: usageContext,
    meta: { source },
  };
}

function sanitizeUsageContextForUpload(
  usageContext: VerimuReport['usageContext'],
): Omit<UsageContextResult, 'artifactPath'> | undefined {
  if (!usageContext) {
    return undefined;
  }

  const { artifactPath: _artifactPath, ...rest } = usageContext;
  return rest;
}

