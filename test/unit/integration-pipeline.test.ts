import { describe, it, expect, afterEach } from 'vitest';
import { scan } from '../../src/scan.js';
import { ConsoleReporter } from '../../src/reporters/console.js';
import { existsSync, unlinkSync } from 'fs';
import { readFile } from 'fs/promises';
import path from 'path';

const FIXTURES = path.resolve(__dirname, '../fixtures');

function relatedArtifactPaths(cycloneDxOutput: string) {
  return {
    spdx: cycloneDxOutput.replace(/\.cdx\.json$/, '.spdx.json'),
    swid: cycloneDxOutput.replace(/\.cdx\.json$/, '.swid.xml'),
  };
}

function cleanupArtifacts(cycloneDxOutput: string) {
  const paths = [cycloneDxOutput, relatedArtifactPaths(cycloneDxOutput).spdx, relatedArtifactPaths(cycloneDxOutput).swid];
  for (const filePath of paths) {
    if (existsSync(filePath)) unlinkSync(filePath);
  }
}

/**
 * Integration tests: Full scan pipeline for every supported ecosystem.
 *
 * Each test runs the complete Verimu workflow:
 *   1. Detect ecosystem from project files
 *   2. Parse lockfile / dependency file
 *   3. Generate CycloneDX SBOM
 *   4. Write SBOM to disk
 *   5. Generate report
 *
 * CVE checking is skipped to avoid network calls in tests.
 */

describe('Full Pipeline — NuGet (.NET)', () => {
  const sbomOutput = path.join(FIXTURES, 'dotnet-api', 'test-sbom.cdx.json');

  afterEach(() => {
    cleanupArtifacts(sbomOutput);
  });

  it('scans dotnet-api fixture end-to-end', async () => {
    const report = await scan({
      projectPath: path.join(FIXTURES, 'dotnet-api'),
      sbomOutput,
      skipCveCheck: true,
    });

    expect(report.project.ecosystem).toBe('nuget');
    expect(report.project.dependencyCount).toBe(6);

    // SBOM was generated
    expect(report.sbom.format).toBe('cyclonedx-json');
    expect(report.sbom.componentCount).toBe(6);

    // SBOM file was written
    expect(existsSync(sbomOutput)).toBe(true);
    const sbomContent = await readFile(sbomOutput, 'utf-8');
    const bom = JSON.parse(sbomContent);
    expect(bom.bomFormat).toBe('CycloneDX');
    expect(bom.specVersion).toBe('1.7');
    expect(bom.components.length).toBe(6);

    // Verify NuGet purls in the SBOM
    const newtonsoft = bom.components.find((c: any) => c.name === 'Newtonsoft.Json');
    expect(newtonsoft).toBeDefined();
    expect(newtonsoft.purl).toBe('pkg:nuget/Newtonsoft.Json@13.0.3');
  });

  it('produces a console report', async () => {
    const report = await scan({
      projectPath: path.join(FIXTURES, 'dotnet-api'),
      sbomOutput,
      skipCveCheck: true,
    });

    const reporter = new ConsoleReporter();
    const output = reporter.report(report);
    expect(output).toContain('nuget');
    expect(output).toContain('SBOM generated');
  });
});

describe('Full Pipeline — NuGet (.NET real-world)', () => {
  const sbomOutput = path.join(FIXTURES, 'dotnet-webapi', 'test-sbom.cdx.json');

  afterEach(() => {
    cleanupArtifacts(sbomOutput);
  });

  it('scans dotnet-webapi fixture end-to-end', async () => {
    const report = await scan({
      projectPath: path.join(FIXTURES, 'dotnet-webapi'),
      sbomOutput,
      skipCveCheck: true,
    });

    expect(report.project.ecosystem).toBe('nuget');
    expect(report.project.dependencyCount).toBe(20);
    expect(report.sbom.componentCount).toBe(20);
  });
});

describe('Full Pipeline — pip (Python)', () => {
  const sbomOutput = path.join(FIXTURES, 'python-api', 'test-sbom.cdx.json');

  afterEach(() => {
    cleanupArtifacts(sbomOutput);
  });

  it('scans python-api fixture end-to-end', async () => {
    const report = await scan({
      projectPath: path.join(FIXTURES, 'python-api'),
      sbomOutput,
      skipCveCheck: true,
    });

    expect(report.project.ecosystem).toBe('pip');
    expect(report.project.dependencyCount).toBe(6);

    // SBOM was generated
    expect(report.sbom.format).toBe('cyclonedx-json');
    expect(report.sbom.componentCount).toBe(6);

    // SBOM file was written
    expect(existsSync(sbomOutput)).toBe(true);
    const sbomContent = await readFile(sbomOutput, 'utf-8');
    const bom = JSON.parse(sbomContent);
    expect(bom.bomFormat).toBe('CycloneDX');

    // Verify PyPI purls
    const flask = bom.components.find((c: any) => c.name === 'flask');
    expect(flask).toBeDefined();
    expect(flask.purl).toBe('pkg:pypi/flask@3.0.0');
  });
});

describe('Full Pipeline — pip (Python Pipfile.lock)', () => {
  const sbomOutput = path.join(FIXTURES, 'python-webapp', 'test-sbom.cdx.json');

  afterEach(() => {
    cleanupArtifacts(sbomOutput);
  });

  it('scans python-webapp fixture end-to-end', async () => {
    const report = await scan({
      projectPath: path.join(FIXTURES, 'python-webapp'),
      sbomOutput,
      skipCveCheck: true,
    });

    expect(report.project.ecosystem).toBe('pip');
    expect(report.project.dependencyCount).toBe(12);
    expect(report.sbom.componentCount).toBe(12);
  });
});

describe('Full Pipeline — Cargo (Rust)', () => {
  const sbomOutput = path.join(FIXTURES, 'rust-cli', 'test-sbom.cdx.json');

  afterEach(() => {
    cleanupArtifacts(sbomOutput);
  });

  it('scans rust-cli fixture end-to-end', async () => {
    const report = await scan({
      projectPath: path.join(FIXTURES, 'rust-cli'),
      sbomOutput,
      skipCveCheck: true,
    });

    expect(report.project.ecosystem).toBe('cargo');
    expect(report.project.dependencyCount).toBe(8);

    // SBOM was generated
    expect(report.sbom.format).toBe('cyclonedx-json');
    expect(report.sbom.componentCount).toBe(8);

    // SBOM file was written
    expect(existsSync(sbomOutput)).toBe(true);
    const sbomContent = await readFile(sbomOutput, 'utf-8');
    const bom = JSON.parse(sbomContent);
    expect(bom.bomFormat).toBe('CycloneDX');

    // Verify Cargo purls
    const serde = bom.components.find((c: any) => c.name === 'serde');
    expect(serde).toBeDefined();
    expect(serde.purl).toBe('pkg:cargo/serde@1.0.195');
  });
});

describe('Full Pipeline — Cargo (Rust real-world)', () => {
  const sbomOutput = path.join(FIXTURES, 'rust-webserver', 'test-sbom.cdx.json');

  afterEach(() => {
    cleanupArtifacts(sbomOutput);
  });

  it('scans rust-webserver fixture end-to-end', async () => {
    const report = await scan({
      projectPath: path.join(FIXTURES, 'rust-webserver'),
      sbomOutput,
      skipCveCheck: true,
    });

    expect(report.project.ecosystem).toBe('cargo');
    expect(report.project.dependencyCount).toBe(14);
    expect(report.sbom.componentCount).toBe(14);
  });
});

describe('Full Pipeline — Maven (Java)', () => {
  const sbomOutput = path.join(FIXTURES, 'java-api', 'test-sbom.cdx.json');

  afterEach(() => {
    cleanupArtifacts(sbomOutput);
  });

  it('scans java-api fixture end-to-end (via dependency-tree.txt)', async () => {
    const report = await scan({
      projectPath: path.join(FIXTURES, 'java-api'),
      sbomOutput,
      skipCveCheck: true,
    });

    expect(report.project.ecosystem).toBe('maven');
    expect(report.project.dependencyCount).toBeGreaterThan(0);

    // SBOM was generated
    expect(report.sbom.format).toBe('cyclonedx-json');

    // SBOM file was written
    expect(existsSync(sbomOutput)).toBe(true);
    const sbomContent = await readFile(sbomOutput, 'utf-8');
    const bom = JSON.parse(sbomContent);
    expect(bom.bomFormat).toBe('CycloneDX');

    // Verify Maven purls
    const guava = bom.components.find((c: any) => c.name === 'com.google.guava:guava');
    expect(guava).toBeDefined();
    expect(guava.purl).toBe('pkg:maven/com.google.guava/guava@32.1.3-jre');
  });
});

describe('Full Pipeline — Maven (Java real-world)', () => {
  const sbomOutput = path.join(FIXTURES, 'java-spring', 'test-sbom.cdx.json');

  afterEach(() => {
    cleanupArtifacts(sbomOutput);
  });

  it('scans java-spring fixture end-to-end', async () => {
    const report = await scan({
      projectPath: path.join(FIXTURES, 'java-spring'),
      sbomOutput,
      skipCveCheck: true,
    });

    expect(report.project.ecosystem).toBe('maven');
    expect(report.project.dependencyCount).toBeGreaterThan(20);
  });
});

describe('Full Pipeline — Go', () => {
  const sbomOutput = path.join(FIXTURES, 'go-api', 'test-sbom.cdx.json');

  afterEach(() => {
    cleanupArtifacts(sbomOutput);
  });

  it('scans go-api fixture end-to-end', async () => {
    const report = await scan({
      projectPath: path.join(FIXTURES, 'go-api'),
      sbomOutput,
      skipCveCheck: true,
    });

    expect(report.project.ecosystem).toBe('go');
    expect(report.project.dependencyCount).toBe(9);

    // SBOM was generated
    expect(report.sbom.format).toBe('cyclonedx-json');
    expect(report.sbom.componentCount).toBe(9);

    // SBOM file was written
    expect(existsSync(sbomOutput)).toBe(true);
    const sbomContent = await readFile(sbomOutput, 'utf-8');
    const bom = JSON.parse(sbomContent);
    expect(bom.bomFormat).toBe('CycloneDX');

    // Verify Go purls
    const gin = bom.components.find((c: any) => c.name === 'github.com/gin-gonic/gin');
    expect(gin).toBeDefined();
    expect(gin.purl).toBe('pkg:golang/github.com/gin-gonic/gin@v1.9.1');
  });

  it('produces a console report', async () => {
    const report = await scan({
      projectPath: path.join(FIXTURES, 'go-api'),
      sbomOutput,
      skipCveCheck: true,
    });

    const reporter = new ConsoleReporter();
    const output = reporter.report(report);
    expect(output).toContain('go');
    expect(output).toContain('SBOM generated');
  });
});

describe('Full Pipeline — Go (real-world)', () => {
  const sbomOutput = path.join(FIXTURES, 'go-service', 'test-sbom.cdx.json');

  afterEach(() => {
    cleanupArtifacts(sbomOutput);
  });

  it('scans go-service fixture end-to-end', async () => {
    const report = await scan({
      projectPath: path.join(FIXTURES, 'go-service'),
      sbomOutput,
      skipCveCheck: true,
    });

    expect(report.project.ecosystem).toBe('go');
    expect(report.project.dependencyCount).toBe(22);
    expect(report.sbom.componentCount).toBe(22);
  });
});

describe('Full Pipeline — Ruby', () => {
  const sbomOutput = path.join(FIXTURES, 'ruby-api', 'test-sbom.cdx.json');

  afterEach(() => {
    cleanupArtifacts(sbomOutput);
  });

  it('scans ruby-api fixture end-to-end', async () => {
    const report = await scan({
      projectPath: path.join(FIXTURES, 'ruby-api'),
      sbomOutput,
      skipCveCheck: true,
    });

    expect(report.project.ecosystem).toBe('ruby');
    expect(report.project.dependencyCount).toBe(10);

    // SBOM was generated
    expect(report.sbom.format).toBe('cyclonedx-json');
    expect(report.sbom.componentCount).toBe(10);

    // SBOM file was written
    expect(existsSync(sbomOutput)).toBe(true);
    const sbomContent = await readFile(sbomOutput, 'utf-8');
    const bom = JSON.parse(sbomContent);
    expect(bom.bomFormat).toBe('CycloneDX');

    // Verify gem purls
    const sinatra = bom.components.find((c: any) => c.name === 'sinatra');
    expect(sinatra).toBeDefined();
    expect(sinatra.purl).toBe('pkg:gem/sinatra@4.0.0');
  });

  it('produces a console report', async () => {
    const report = await scan({
      projectPath: path.join(FIXTURES, 'ruby-api'),
      sbomOutput,
      skipCveCheck: true,
    });

    const reporter = new ConsoleReporter();
    const output = reporter.report(report);
    expect(output).toContain('ruby');
    expect(output).toContain('SBOM generated');
  });
});

describe('Full Pipeline — Ruby (real-world)', () => {
  const sbomOutput = path.join(FIXTURES, 'ruby-service', 'test-sbom.cdx.json');

  afterEach(() => {
    cleanupArtifacts(sbomOutput);
  });

  it('scans ruby-service fixture end-to-end', async () => {
    const report = await scan({
      projectPath: path.join(FIXTURES, 'ruby-service'),
      sbomOutput,
      skipCveCheck: true,
    });

    expect(report.project.ecosystem).toBe('ruby');
    expect(report.project.dependencyCount).toBe(40);
    expect(report.sbom.componentCount).toBe(40);
  });
});

describe('Cross-ecosystem SBOM compliance', () => {
  it('all ecosystems produce NTIA-compliant SBOMs with supplier fields', async () => {
    const projects = [
      { fixture: 'dotnet-api', expectedEcosystem: 'nuget' },
      { fixture: 'python-api', expectedEcosystem: 'pip' },
      { fixture: 'rust-cli', expectedEcosystem: 'cargo' },
      { fixture: 'java-api', expectedEcosystem: 'maven' },
      { fixture: 'node-api', expectedEcosystem: 'npm' },
      { fixture: 'go-api', expectedEcosystem: 'go' },
      { fixture: 'ruby-api', expectedEcosystem: 'ruby' },
    ];

    for (const { fixture, expectedEcosystem } of projects) {
      const sbomOutput = path.join(FIXTURES, fixture, 'ntia-test-sbom.cdx.json');
      try {
        const report = await scan({
          projectPath: path.join(FIXTURES, fixture),
          sbomOutput,
          skipCveCheck: true,
        });

        expect(report.project.ecosystem).toBe(expectedEcosystem);

        const bom = JSON.parse(report.sbom.content);

        // NTIA: metadata.supplier
        expect(bom.metadata.supplier).toBeDefined();
        expect(bom.metadata.supplier.name).toBeTruthy();

        // NTIA: component.supplier on every component
        for (const component of bom.components) {
          expect(component.supplier).toBeDefined();
          expect(component.supplier.name).toBeTruthy();
          expect(component.purl).toBeTruthy();
          expect(component['bom-ref']).toBeTruthy();
        }

        // NTIA: dependency graph with single root
        expect(bom.dependencies).toBeDefined();
        expect(bom.dependencies.length).toBe(1);
        expect(bom.dependencies[0].ref).toBe('root-component');
      } finally {
        cleanupArtifacts(sbomOutput);
      }
    }
  });
});
