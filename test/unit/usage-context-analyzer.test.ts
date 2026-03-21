import { mkdtemp, rm, writeFile, mkdir } from 'fs/promises';
import os from 'os';
import path from 'path';
import { describe, it, expect } from 'vitest';
import { JsAstAnalyzer } from '../../src/context/analyzers/js-ast-analyzer.js';

async function withTempProject(run: (projectPath: string) => Promise<void>): Promise<void> {
  const tmpDir = await mkdtemp(path.join(os.tmpdir(), 'verimu-usage-analyzer-'));
  try {
    await run(tmpDir);
  } finally {
    await rm(tmpDir, { recursive: true, force: true });
  }
}

describe('JsAstAnalyzer', () => {
  it('finds direct evidence from imports and calls', async () => {
    await withTempProject(async (projectPath) => {
      const srcDir = path.join(projectPath, 'src');
      await mkdir(srcDir, { recursive: true });

      await writeFile(
        path.join(srcDir, 'index.ts'),
        [
          'import express from "express";',
          'const app = express();',
          'app.listen(3000);',
        ].join('\n'),
        'utf-8',
      );

      const analyzer = new JsAstAnalyzer();
      const result = await analyzer.analyze({
        projectPath,
        ecosystem: 'npm',
        numContextLines: 2,
        maxSnippetsPerPackage: 20,
        maxSnippetsTotal: 100,
        packages: [
          {
            packageName: 'express',
            ecosystem: 'npm',
            directDependency: true,
            vulnerabilities: [],
          },
        ],
      });

      expect(result.errors).toHaveLength(0);
      expect(result.packages).toHaveLength(1);
      expect(result.packages[0].status).toBe('direct_evidence');
      expect(result.packages[0].snippets.length).toBeGreaterThan(0);
      expect(result.packages[0].snippets.some((snippet) => snippet.matchKind === 'import')).toBe(true);
      expect(result.packages[0].snippets.some((snippet) => snippet.matchKind === 'call')).toBe(true);
    });
  });

  it('returns indirect_no_evidence when no vulnerable package usage is found', async () => {
    await withTempProject(async (projectPath) => {
      const srcDir = path.join(projectPath, 'src');
      await mkdir(srcDir, { recursive: true });

      await writeFile(
        path.join(srcDir, 'index.ts'),
        'import fs from "node:fs";\nconsole.log(fs.existsSync("."));\n',
        'utf-8',
      );

      const analyzer = new JsAstAnalyzer();
      const result = await analyzer.analyze({
        projectPath,
        ecosystem: 'npm',
        numContextLines: 2,
        maxSnippetsPerPackage: 20,
        maxSnippetsTotal: 100,
        packages: [
          {
            packageName: 'express',
            ecosystem: 'npm',
            directDependency: false,
            vulnerabilities: [],
          },
        ],
      });

      expect(result.errors).toHaveLength(0);
      expect(result.packages[0].status).toBe('indirect_no_evidence');
      expect(result.packages[0].snippets).toHaveLength(0);
    });
  });

  it('continues when a file cannot be parsed', async () => {
    await withTempProject(async (projectPath) => {
      const srcDir = path.join(projectPath, 'src');
      await mkdir(srcDir, { recursive: true });

      await writeFile(
        path.join(srcDir, 'broken.js'),
        'import express from "express"\nfunction () {',
        'utf-8',
      );

      const analyzer = new JsAstAnalyzer();
      const result = await analyzer.analyze({
        projectPath,
        ecosystem: 'npm',
        numContextLines: 2,
        maxSnippetsPerPackage: 20,
        maxSnippetsTotal: 100,
        packages: [
          {
            packageName: 'express',
            ecosystem: 'npm',
            directDependency: true,
            vulnerabilities: [],
          },
        ],
      });

      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.packages).toHaveLength(1);
      expect(result.packages[0].status).toBe('indirect_no_evidence');
    });
  });
});
