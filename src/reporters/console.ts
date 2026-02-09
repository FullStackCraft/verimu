import type { Reporter } from './reporter.interface.js';
import type { VerimuReport, Vulnerability, Severity } from '../core/types.js';

/** Outputs a human-readable console report */
export class ConsoleReporter implements Reporter {
  readonly name = 'console';

  report(result: VerimuReport): string {
    const lines: string[] = [];

    lines.push('');
    lines.push('┌─────────────────────────────────────────────┐');
    lines.push('│          VERIMU CRA COMPLIANCE SCAN         │');
    lines.push('└─────────────────────────────────────────────┘');
    lines.push('');

    // Project info
    lines.push(`  Project:      ${result.project.path}`);
    lines.push(`  Ecosystem:    ${result.project.ecosystem}`);
    lines.push(`  Dependencies: ${result.project.dependencyCount}`);
    lines.push(`  Scanned at:   ${result.generatedAt}`);
    lines.push('');

    // SBOM info
    lines.push(`  ✓ SBOM generated (${result.sbom.format}, ${result.sbom.specVersion})`);
    lines.push(`    Components: ${result.sbom.componentCount}`);
    lines.push('');

    // CVE results
    const vulns = result.cveCheck.vulnerabilities;
    if (vulns.length === 0) {
      lines.push('  ✓ No known vulnerabilities found');
    } else {
      lines.push(`  ⚠ ${vulns.length} vulnerabilit${vulns.length === 1 ? 'y' : 'ies'} found:`);
      lines.push('');

      // Sort by severity: CRITICAL → HIGH → MEDIUM → LOW → UNKNOWN
      const sorted = [...vulns].sort((a, b) => severityOrder(a.severity) - severityOrder(b.severity));

      for (const vuln of sorted) {
        const badge = severityBadge(vuln.severity);
        const fix = vuln.fixedVersion ? ` → fix: ${vuln.fixedVersion}` : '';
        lines.push(`    ${badge}  ${vuln.id}`);
        lines.push(`           ${vuln.packageName}@${vuln.affectedVersionRange ?? '?'}${fix}`);
        lines.push(`           ${vuln.summary.slice(0, 100)}`);
        if (vuln.exploitedInWild) {
          lines.push(`           🔴 ACTIVELY EXPLOITED — 24h CRA reporting required`);
        }
        lines.push('');
      }
    }

    // Sources
    const sources = result.cveCheck.sourcesQueried.join(', ');
    lines.push(`  Sources queried: ${sources} (${result.cveCheck.checkDurationMs}ms)`);

    if (result.cveCheck.sourceErrors.length > 0) {
      for (const err of result.cveCheck.sourceErrors) {
        lines.push(`  ⚠ ${err.source}: ${err.error}`);
      }
    }

    // Summary
    lines.push('');
    lines.push('  ─── Summary ───');
    lines.push(`  Total: ${result.summary.totalVulnerabilities}  |  ` +
      `Critical: ${result.summary.critical}  |  ` +
      `High: ${result.summary.high}  |  ` +
      `Medium: ${result.summary.medium}  |  ` +
      `Low: ${result.summary.low}`);

    if (result.summary.exploitedInWild > 0) {
      lines.push(`  🔴 ${result.summary.exploitedInWild} actively exploited — immediate action required`);
    }

    lines.push('');
    return lines.join('\n');
  }
}

function severityOrder(s: Severity): number {
  const order: Record<Severity, number> = {
    CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNKNOWN: 4,
  };
  return order[s] ?? 5;
}

function severityBadge(s: Severity): string {
  const badges: Record<Severity, string> = {
    CRITICAL: '[CRIT]',
    HIGH: '[HIGH]',
    MEDIUM: '[MED] ',
    LOW: '[LOW] ',
    UNKNOWN: '[???] ',
  };
  return badges[s] ?? '[???] ';
}
