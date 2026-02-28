import type { Severity } from '../core/types.js';
import type { ScanResponse } from '../api/client.js';
import type { UploadResult } from '../scan.js';

type PlatformScanResult = ScanResponse['scan_results'][number];
type BackendVulnerability = NonNullable<PlatformScanResult['vulnerabilities']>[number];

type PlatformVulnerability = {
  dependencyName: string;
  version: string;
  cveId: string;
  severity: Severity;
  summary: string;
  fixedVersion: string | null;
};

export function renderPlatformScan(projectPath: string, result: UploadResult): string {
  const lines: string[] = [];
  const vulns = collectVulnerabilities(result);
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
      lines.push(`           ${(vuln.summary ?? '').slice(0, 100)}`);
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

function collectVulnerabilities(result: UploadResult): PlatformVulnerability[] {
  return (result.scanResponse.scan_results ?? []).flatMap((scanResult) =>
    (scanResult.vulnerabilities ?? []).map((vuln) => ({
      dependencyName: scanResult.dependency_name,
      version: scanResult.version,
      cveId: vuln.cve_id,
      severity: normalizeSeverity(vuln.severity ?? 'UNKNOWN'),
      summary: pickSummary(vuln),
      fixedVersion: pickFixedVersion(vuln),
    }))
  );
}

function pickSummary(vuln: BackendVulnerability): string {
  const value = vuln.summary ?? vuln.description;
  if (typeof value !== 'string' || value.trim() === '') {
    return 'No description available';
  }
  return value;
}

function pickFixedVersion(vuln: BackendVulnerability): string | null {
  if (typeof vuln.fixed_version === 'string' && vuln.fixed_version.trim() !== '') {
    return vuln.fixed_version;
  }

  for (const source of vuln.sources ?? []) {
    const fixedVersion = source.data?.fixed_version;
    if (typeof fixedVersion === 'string' && fixedVersion.trim() !== '') {
      return fixedVersion;
    }
  }

  return null;
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
