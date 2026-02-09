import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { scan, shouldFailCi, printReport } from '../../src/scan.js';
import { ConsoleReporter } from '../../src/reporters/console.js';
import { NpmScanner } from '../../src/scanners/npm/npm-scanner.js';
import { CycloneDxGenerator } from '../../src/sbom/cyclonedx.js';
import path from 'path';
import { existsSync, unlinkSync } from 'fs';
import { readFile } from 'fs/promises';
import type { VerimuReport } from '../../src/core/types.js';

const FIXTURES = path.resolve(__dirname, '../fixtures');
const SBOM_OUTPUT = path.join(FIXTURES, 'node-api', 'test-sbom.cdx.json');

describe('Full Pipeline — scan()', () => {
  afterEach(() => {
    // Clean up generated SBOM
    // if (existsSync(SBOM_OUTPUT)) unlinkSync(SBOM_OUTPUT);
  });

  it('scans node-api fixture end-to-end (skip CVE to avoid network)', async () => {
    const report = await scan({
      projectPath: path.join(FIXTURES, 'node-api'),
      sbomOutput: SBOM_OUTPUT,
      skipCveCheck: true,
    });

    // Project
    expect(report.project.ecosystem).toBe('npm');
    expect(report.project.dependencyCount).toBeGreaterThan(5);

    // SBOM was generated
    expect(report.sbom.format).toBe('cyclonedx-json');
    expect(report.sbom.componentCount).toBe(report.project.dependencyCount);

    // SBOM file was written
    expect(existsSync(SBOM_OUTPUT)).toBe(true);
    const sbomContent = await readFile(SBOM_OUTPUT, 'utf-8');
    const bom = JSON.parse(sbomContent);
    expect(bom.bomFormat).toBe('CycloneDX');
    expect(bom.components.length).toBe(report.project.dependencyCount);

    // CVE check was skipped
    expect(report.cveCheck.vulnerabilities).toHaveLength(0);
    expect(report.cveCheck.sourcesQueried).toHaveLength(0);

    // Summary
    expect(report.summary.totalDependencies).toBe(report.project.dependencyCount);
    expect(report.summary.totalVulnerabilities).toBe(0);
  });

  it('generates a valid SBOM file for vue-app', async () => {
    const output = path.join(FIXTURES, 'vue-app', 'test-sbom.cdx.json');
    try {
      const report = await scan({
        projectPath: path.join(FIXTURES, 'vue-app'),
        sbomOutput: output,
        skipCveCheck: true,
      });

      expect(report.project.ecosystem).toBe('npm');
      expect(report.project.dependencyCount).toBe(6); // vue, pinia, vue-router, vite, plugin-vue, @vue/reactivity

      const sbomContent = await readFile(output, 'utf-8');
      const bom = JSON.parse(sbomContent);

      // Verify Vue is in the SBOM
      const vue = bom.components.find((c: any) => c.name === 'vue');
      expect(vue).toBeDefined();
      expect(vue.version).toBe('3.4.15');
      expect(vue.purl).toBe('pkg:npm/vue@3.4.15');
    } finally {
      if (existsSync(output)) unlinkSync(output);
    }
  });
});

describe('shouldFailCi()', () => {
  const baseReport: VerimuReport = {
    project: { path: '/test', ecosystem: 'npm', dependencyCount: 10 },
    sbom: { format: 'cyclonedx-json', specVersion: '1.7', content: '{}', componentCount: 10, generatedAt: '' },
    cveCheck: { vulnerabilities: [], sourcesQueried: ['osv'], sourceErrors: [], checkDurationMs: 100 },
    summary: { totalDependencies: 10, totalVulnerabilities: 0, critical: 0, high: 0, medium: 0, low: 0, exploitedInWild: 0 },
    generatedAt: '',
  };

  it('returns false when no vulnerabilities', () => {
    expect(shouldFailCi(baseReport, 'HIGH')).toBe(false);
  });

  it('returns true when vuln meets threshold', () => {
    const report: VerimuReport = {
      ...baseReport,
      cveCheck: {
        ...baseReport.cveCheck,
        vulnerabilities: [
          {
            id: 'CVE-2024-1234', aliases: [], summary: 'test', severity: 'HIGH',
            packageName: 'test', ecosystem: 'npm', exploitedInWild: false, source: 'osv',
          },
        ],
      },
    };
    expect(shouldFailCi(report, 'HIGH')).toBe(true);
    expect(shouldFailCi(report, 'CRITICAL')).toBe(false); // HIGH doesn't meet CRITICAL threshold
  });
});

describe('ConsoleReporter', () => {
  it('formats a clean report with no vulns', async () => {
    const report = await scan({
      projectPath: path.join(FIXTURES, 'node-api'),
      sbomOutput: SBOM_OUTPUT,
      skipCveCheck: true,
    });

    const reporter = new ConsoleReporter();
    const output = reporter.report(report);

    expect(output).toContain('VERIMU CRA COMPLIANCE SCAN');
    expect(output).toContain('node-api');
    expect(output).toContain('npm');
    expect(output).toContain('No known vulnerabilities found');
    expect(output).toContain('SBOM generated');

    // Clean up
    if (existsSync(SBOM_OUTPUT)) unlinkSync(SBOM_OUTPUT);
  });

  it('formats vulnerabilities with severity badges', () => {
    const reporter = new ConsoleReporter();
    const report: VerimuReport = {
      project: { path: '/test/my-app', ecosystem: 'npm', dependencyCount: 5 },
      sbom: { format: 'cyclonedx-json', specVersion: '1.7', content: '{}', componentCount: 5, generatedAt: '' },
      cveCheck: {
        vulnerabilities: [
          {
            id: 'CVE-2024-1234', aliases: [], summary: 'Critical RCE in express',
            severity: 'CRITICAL', cvssScore: 9.8, packageName: 'express', ecosystem: 'npm',
            affectedVersionRange: '>=4.0.0, <4.19.2', fixedVersion: '4.19.2',
            exploitedInWild: true, source: 'osv',
          },
          {
            id: 'CVE-2024-5678', aliases: [], summary: 'Medium XSS in lodash',
            severity: 'MEDIUM', packageName: 'lodash', ecosystem: 'npm',
            exploitedInWild: false, source: 'osv',
          },
        ],
        sourcesQueried: ['osv'],
        sourceErrors: [],
        checkDurationMs: 150,
      },
      summary: { totalDependencies: 5, totalVulnerabilities: 2, critical: 1, high: 0, medium: 1, low: 0, exploitedInWild: 1 },
      generatedAt: new Date().toISOString(),
    };

    const output = reporter.report(report);

    expect(output).toContain('[CRIT]');
    expect(output).toContain('CVE-2024-1234');
    expect(output).toContain('fix: 4.19.2');
    expect(output).toContain('ACTIVELY EXPLOITED');
    expect(output).toContain('[MED]');
    expect(output).toContain('CVE-2024-5678');
    expect(output).toContain('Critical: 1');
    expect(output).toContain('Medium: 1');
  });
});
