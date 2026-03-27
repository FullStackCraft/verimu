import { describe, it, expect, afterEach } from 'vitest';
import { NpmScanner } from '../../src/scanners/npm/npm-scanner.js';
import { PnpmScanner } from '../../src/scanners/pnpm/pnpm-scanner.js';
import { scan } from '../../src/scan.js';
import { parseArgs } from '../../src/cli.js';
import path from 'path';
import { existsSync, unlinkSync, readdirSync } from 'fs';

const FIXTURES = path.resolve(__dirname, '../fixtures');

function cleanupArtifacts(dir: string, prefix: string) {
  const files = readdirSync(dir);
  for (const file of files) {
    if (file.startsWith(prefix) && (file.endsWith('.json') || file.endsWith('.xml'))) {
      const filePath = path.join(dir, file);
      if (existsSync(filePath)) unlinkSync(filePath);
    }
  }
}

describe('Multi-Project Independent — Separate Lock Files', () => {
  const MULTI_PROJECT_DIR = path.join(FIXTURES, 'multi-project-independent');
  const npmScanner = new NpmScanner();

  afterEach(() => {
    // Clean up any generated artifacts
    cleanupArtifacts(path.join(MULTI_PROJECT_DIR, 'api'), 'test-sbom');
    cleanupArtifacts(path.join(MULTI_PROJECT_DIR, 'frontend'), 'test-sbom');
    cleanupArtifacts(path.join(MULTI_PROJECT_DIR, 'mobile'), 'test-sbom');
  });

  describe('Scanner Detection', () => {
    it('detects lockfile in api subdirectory', async () => {
      const result = await npmScanner.detect(path.join(MULTI_PROJECT_DIR, 'api'));
      expect(result).not.toBeNull();
      expect(result).toContain('package-lock.json');
    });

    it('detects lockfile in frontend subdirectory', async () => {
      const result = await npmScanner.detect(path.join(MULTI_PROJECT_DIR, 'frontend'));
      expect(result).not.toBeNull();
      expect(result).toContain('package-lock.json');
    });

    it('detects lockfile in mobile subdirectory', async () => {
      const result = await npmScanner.detect(path.join(MULTI_PROJECT_DIR, 'mobile'));
      expect(result).not.toBeNull();
      expect(result).toContain('package-lock.json');
    });

    it('does NOT detect lockfile in parent directory (no root lockfile)', async () => {
      const result = await npmScanner.detect(MULTI_PROJECT_DIR);
      expect(result).toBeNull();
    });
  });

  describe('Independent Scanning', () => {
    it('scans api project independently', async () => {
      const lockfilePath = path.join(MULTI_PROJECT_DIR, 'api', 'package-lock.json');
      const result = await npmScanner.scan(path.join(MULTI_PROJECT_DIR, 'api'), lockfilePath);

      expect(result.ecosystem).toBe('npm');
      expect(result.dependencies.length).toBe(2);

      const names = result.dependencies.map((d) => d.name).sort();
      expect(names).toEqual(['express', 'jsonwebtoken']);
    });

    it('scans frontend project independently', async () => {
      const lockfilePath = path.join(MULTI_PROJECT_DIR, 'frontend', 'package-lock.json');
      const result = await npmScanner.scan(path.join(MULTI_PROJECT_DIR, 'frontend'), lockfilePath);

      expect(result.ecosystem).toBe('npm');
      expect(result.dependencies.length).toBe(2);

      const names = result.dependencies.map((d) => d.name).sort();
      expect(names).toEqual(['axios', 'react']);
    });

    it('scans mobile project independently', async () => {
      const lockfilePath = path.join(MULTI_PROJECT_DIR, 'mobile', 'package-lock.json');
      const result = await npmScanner.scan(path.join(MULTI_PROJECT_DIR, 'mobile'), lockfilePath);

      expect(result.ecosystem).toBe('npm');
      expect(result.dependencies.length).toBe(2);

      const names = result.dependencies.map((d) => d.name).sort();
      expect(names).toEqual(['lodash', 'react-native']);
    });

    it('each project has completely different dependencies', async () => {
      const apiLock = path.join(MULTI_PROJECT_DIR, 'api', 'package-lock.json');
      const frontendLock = path.join(MULTI_PROJECT_DIR, 'frontend', 'package-lock.json');
      const mobileLock = path.join(MULTI_PROJECT_DIR, 'mobile', 'package-lock.json');

      const apiResult = await npmScanner.scan(path.join(MULTI_PROJECT_DIR, 'api'), apiLock);
      const frontendResult = await npmScanner.scan(path.join(MULTI_PROJECT_DIR, 'frontend'), frontendLock);
      const mobileResult = await npmScanner.scan(path.join(MULTI_PROJECT_DIR, 'mobile'), mobileLock);

      const apiNames = new Set(apiResult.dependencies.map((d) => d.name));
      const frontendNames = new Set(frontendResult.dependencies.map((d) => d.name));
      const mobileNames = new Set(mobileResult.dependencies.map((d) => d.name));

      // No overlap between api and frontend
      const apiOverlapFrontend = [...apiNames].filter((n) => frontendNames.has(n));
      expect(apiOverlapFrontend).toHaveLength(0);

      // No overlap between api and mobile
      const apiOverlapMobile = [...apiNames].filter((n) => mobileNames.has(n));
      expect(apiOverlapMobile).toHaveLength(0);
    });
  });

  describe('Full Pipeline Scan', () => {
    it('scans each subproject with scan() function', async () => {
      const apiReport = await scan({
        projectPath: path.join(MULTI_PROJECT_DIR, 'api'),
        sbomOutput: path.join(MULTI_PROJECT_DIR, 'api', 'test-sbom.cdx.json'),
        skipCveCheck: true,
      });

      expect(apiReport.project.ecosystem).toBe('npm');
      expect(apiReport.project.dependencyCount).toBe(2);
      expect(apiReport.sbom.componentCount).toBe(2);

      const frontendReport = await scan({
        projectPath: path.join(MULTI_PROJECT_DIR, 'frontend'),
        sbomOutput: path.join(MULTI_PROJECT_DIR, 'frontend', 'test-sbom.cdx.json'),
        skipCveCheck: true,
      });

      expect(frontendReport.project.ecosystem).toBe('npm');
      expect(frontendReport.project.dependencyCount).toBe(2);
    });
  });
});

describe('npm Monorepo — Single Lock File with Workspaces', () => {
  const MONOREPO_DIR = path.join(FIXTURES, 'npm-monorepo');
  const npmScanner = new NpmScanner();

  afterEach(() => {
    cleanupArtifacts(MONOREPO_DIR, 'test-sbom');
  });

  describe('Scanner Detection', () => {
    it('detects single lockfile at monorepo root', async () => {
      const result = await npmScanner.detect(MONOREPO_DIR);
      expect(result).not.toBeNull();
      expect(result).toContain('package-lock.json');
    });

    it('does NOT detect lockfile in workspace packages (they use root lockfile)', async () => {
      const apiResult = await npmScanner.detect(path.join(MONOREPO_DIR, 'packages', 'api'));
      expect(apiResult).toBeNull();

      const webResult = await npmScanner.detect(path.join(MONOREPO_DIR, 'packages', 'web'));
      expect(webResult).toBeNull();
    });
  });

  describe('Monorepo Scanning', () => {
    it('scans monorepo root and finds all external dependencies', async () => {
      const lockfilePath = path.join(MONOREPO_DIR, 'package-lock.json');
      const result = await npmScanner.scan(MONOREPO_DIR, lockfilePath);

      expect(result.ecosystem).toBe('npm');
      // Should have: express, lodash, react, typescript (external deps)
      // Should NOT have: @my-monorepo/* (workspace links)
      const names = result.dependencies.map((d) => d.name).sort();

      expect(names).toContain('express');
      expect(names).toContain('lodash');
      expect(names).toContain('react');
      expect(names).toContain('typescript');

      // Workspace packages should be excluded (link: true)
      expect(names).not.toContain('@my-monorepo/api');
      expect(names).not.toContain('@my-monorepo/web');
      expect(names).not.toContain('@my-monorepo/shared');
    });

    it('marks dependencies correctly as direct vs transitive', async () => {
      const lockfilePath = path.join(MONOREPO_DIR, 'package-lock.json');
      const result = await npmScanner.scan(MONOREPO_DIR, lockfilePath);

      // typescript is a devDependency of root
      const typescript = result.dependencies.find((d) => d.name === 'typescript');
      expect(typescript).toBeDefined();
      expect(typescript?.direct).toBe(true);
    });
  });

  describe('Full Pipeline Scan', () => {
    it('scans monorepo as single project', async () => {
      const report = await scan({
        projectPath: MONOREPO_DIR,
        sbomOutput: path.join(MONOREPO_DIR, 'test-sbom.cdx.json'),
        skipCveCheck: true,
      });

      expect(report.project.ecosystem).toBe('npm');
      // All external deps combined: express, lodash, react, typescript = 4
      expect(report.project.dependencyCount).toBe(4);
      expect(report.sbom.componentCount).toBe(4);
    });
  });
});

describe('pnpm Monorepo — Single Lock File with Workspaces', () => {
  const MONOREPO_DIR = path.join(FIXTURES, 'pnpm-monorepo');
  const pnpmScanner = new PnpmScanner();

  afterEach(() => {
    cleanupArtifacts(MONOREPO_DIR, 'test-sbom');
  });

  describe('Scanner Detection', () => {
    it('detects single pnpm-lock.yaml at monorepo root', async () => {
      const result = await pnpmScanner.detect(MONOREPO_DIR);
      expect(result).not.toBeNull();
      expect(result).toContain('pnpm-lock.yaml');
    });

    it('does NOT detect lockfile in workspace packages', async () => {
      const apiResult = await pnpmScanner.detect(path.join(MONOREPO_DIR, 'packages', 'api'));
      expect(apiResult).toBeNull();
    });
  });

  describe('Monorepo Scanning', () => {
    it('scans pnpm monorepo and finds all external dependencies', async () => {
      const lockfilePath = path.join(MONOREPO_DIR, 'pnpm-lock.yaml');
      const result = await pnpmScanner.scan(MONOREPO_DIR, lockfilePath);

      expect(result.ecosystem).toBe('npm'); // pnpm still uses npm ecosystem

      // Should have: fastify, typescript, vue, zod
      // Should NOT have workspace links
      const names = result.dependencies.map((d) => d.name).sort();

      expect(names).toContain('fastify');
      expect(names).toContain('typescript');
      expect(names).toContain('vue');
      expect(names).toContain('zod');

      // Workspace packages should be excluded
      expect(names).not.toContain('@pnpm-monorepo/api');
      expect(names).not.toContain('@pnpm-monorepo/web');
      expect(names).not.toContain('@pnpm-monorepo/shared');
    });
  });

  describe('Full Pipeline Scan', () => {
    it('scans pnpm monorepo as single project', async () => {
      const report = await scan({
        projectPath: MONOREPO_DIR,
        sbomOutput: path.join(MONOREPO_DIR, 'test-sbom.cdx.json'),
        skipCveCheck: true,
      });

      expect(report.project.ecosystem).toBe('npm');
      // All external deps: fastify, typescript, vue, zod = 4
      expect(report.project.dependencyCount).toBe(4);
    });
  });
});

describe('CLI --group-name flag', () => {
  it('parses --group-name flag', () => {
    const args = parseArgs(['node', 'verimu', 'scan', '--group-name', 'my-app']);
    expect(args.groupName).toBe('my-app');
  });

  it('parses --group-name=value format', () => {
    const args = parseArgs(['node', 'verimu', 'scan', '--group-name=my-monorepo']);
    expect(args.groupName).toBe('my-monorepo');
  });

  it('throws for missing --group-name value', () => {
    expect(() => parseArgs(['node', 'verimu', 'scan', '--group-name'])).toThrow(
      '--group-name requires a value',
    );
  });

  it('throws when --group-name is followed by another flag', () => {
    expect(() => parseArgs(['node', 'verimu', 'scan', '--group-name', '--skip-cve'])).toThrow(
      '--group-name requires a value',
    );
  });

  it('combines --group-name with other flags', () => {
    const args = parseArgs([
      'node', 'verimu', 'scan',
      '--path', './backend',
      '--group-name', 'my-app',
      '--fail-on', 'HIGH',
      '--skip-cve',
    ]);

    expect(args.projectPath).toBe('./backend');
    expect(args.groupName).toBe('my-app');
    expect(args.failOnSeverity).toBe('HIGH');
    expect(args.skipCveCheck).toBe(true);
  });

  it('groupName is undefined when not provided', () => {
    const args = parseArgs(['node', 'verimu', 'scan']);
    expect(args.groupName).toBeUndefined();
  });
});
