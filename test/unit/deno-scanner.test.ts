import { describe, it, expect } from 'vitest';
import { DenoScanner } from '../../src/scanners/deno/deno-scanner.js';
import path from 'path';

const FIXTURES = path.resolve(__dirname, '../fixtures');

describe('DenoScanner', () => {
  const scanner = new DenoScanner();

  describe('detect()', () => {
    it('finds deno.lock in a Deno project', async () => {
      const result = await scanner.detect(path.join(FIXTURES, 'deno-api'));
      expect(result).not.toBeNull();
      expect(result).toContain('deno.lock');
    });

    it('returns null for a project with no deno.lock', async () => {
      const result = await scanner.detect(path.join(FIXTURES, 'empty-project'));
      expect(result).toBeNull();
    });

    it('returns null for an npm project', async () => {
      const result = await scanner.detect(path.join(FIXTURES, 'node-api'));
      expect(result).toBeNull();
    });
  });

  describe('scan() — deno-api fixture (v4 lockfile)', () => {
    it('parses all dependencies from deno.lock', async () => {
      const lockfilePath = path.join(FIXTURES, 'deno-api', 'deno.lock');
      const result = await scanner.scan(path.join(FIXTURES, 'deno-api'), lockfilePath);

      expect(result.ecosystem).toBe('deno');
      // 5 JSR packages + 6 npm packages = 11 total
      expect(result.dependencies.length).toBe(11);
    });

    it('parses JSR packages correctly', async () => {
      const lockfilePath = path.join(FIXTURES, 'deno-api', 'deno.lock');
      const result = await scanner.scan(path.join(FIXTURES, 'deno-api'), lockfilePath);

      const stdAssert = result.dependencies.find((d) => d.name === '@std/assert');
      expect(stdAssert).toBeDefined();
      expect(stdAssert?.version).toBe('1.0.10');

      const oakOak = result.dependencies.find((d) => d.name === '@oak/oak');
      expect(oakOak).toBeDefined();
      expect(oakOak?.version).toBe('17.1.4');
    });

    it('parses npm packages correctly', async () => {
      const lockfilePath = path.join(FIXTURES, 'deno-api', 'deno.lock');
      const result = await scanner.scan(path.join(FIXTURES, 'deno-api'), lockfilePath);

      const express = result.dependencies.find((d) => d.name === 'express');
      expect(express).toBeDefined();
      expect(express?.version).toBe('4.21.2');

      const bodyParser = result.dependencies.find((d) => d.name === 'body-parser');
      expect(bodyParser).toBeDefined();
      expect(bodyParser?.version).toBe('1.20.3');
    });

    it('correctly identifies direct vs transitive dependencies', async () => {
      const lockfilePath = path.join(FIXTURES, 'deno-api', 'deno.lock');
      const result = await scanner.scan(path.join(FIXTURES, 'deno-api'), lockfilePath);

      // Direct deps from deno.json imports
      const directDeps = result.dependencies.filter((d) => d.direct);
      const directNames = directDeps.map((d) => d.name).sort();
      expect(directNames).toContain('@std/assert');
      expect(directNames).toContain('@std/http');
      expect(directNames).toContain('@oak/oak');
      expect(directNames).toContain('express');

      // Transitive deps
      const transitiveDeps = result.dependencies.filter((d) => !d.direct);
      const transitiveNames = transitiveDeps.map((d) => d.name).sort();
      expect(transitiveNames).toContain('@std/internal');
      expect(transitiveNames).toContain('@oak/commons');
      expect(transitiveNames).toContain('body-parser');
      expect(transitiveNames).toContain('cookie');
      expect(transitiveNames).toContain('debug');
      expect(transitiveNames).toContain('bytes');
      expect(transitiveNames).toContain('ms');
    });

    it('generates correct JSR purls', async () => {
      const lockfilePath = path.join(FIXTURES, 'deno-api', 'deno.lock');
      const result = await scanner.scan(path.join(FIXTURES, 'deno-api'), lockfilePath);

      const stdAssert = result.dependencies.find((d) => d.name === '@std/assert');
      expect(stdAssert?.purl).toBe('pkg:jsr/%40std%2Fassert@1.0.10');

      const oakOak = result.dependencies.find((d) => d.name === '@oak/oak');
      expect(oakOak?.purl).toBe('pkg:jsr/%40oak%2Foak@17.1.4');
    });

    it('generates correct npm purls for npm-via-deno packages', async () => {
      const lockfilePath = path.join(FIXTURES, 'deno-api', 'deno.lock');
      const result = await scanner.scan(path.join(FIXTURES, 'deno-api'), lockfilePath);

      const express = result.dependencies.find((d) => d.name === 'express');
      expect(express?.purl).toBe('pkg:npm/express@4.21.2');

      const bodyParser = result.dependencies.find((d) => d.name === 'body-parser');
      expect(bodyParser?.purl).toBe('pkg:npm/body-parser@1.20.3');
    });

    it('sets ecosystem to deno for all dependencies', async () => {
      const lockfilePath = path.join(FIXTURES, 'deno-api', 'deno.lock');
      const result = await scanner.scan(path.join(FIXTURES, 'deno-api'), lockfilePath);

      // JSR packages have ecosystem 'deno'
      const jsrDeps = result.dependencies.filter((d) => d.purl?.startsWith('pkg:jsr/'));
      expect(jsrDeps.every((d) => d.ecosystem === 'deno')).toBe(true);
      expect(jsrDeps.length).toBeGreaterThan(0);

      // npm packages have ecosystem 'npm' (for proper CVE tracking)
      const npmDeps = result.dependencies.filter((d) => d.purl?.startsWith('pkg:npm/'));
      expect(npmDeps.every((d) => d.ecosystem === 'npm')).toBe(true);
      expect(npmDeps.length).toBeGreaterThan(0);
    });

    it('sets scannedAt timestamp', async () => {
      const lockfilePath = path.join(FIXTURES, 'deno-api', 'deno.lock');
      const result = await scanner.scan(path.join(FIXTURES, 'deno-api'), lockfilePath);
      expect(result.scannedAt).toBeTruthy();
      expect(new Date(result.scannedAt).getTime()).not.toBeNaN();
    });
  });

  describe('scan() — deno-webapp fixture (v3 lockfile)', () => {
    it('parses a v3 lockfile with packages nested structure', async () => {
      const lockfilePath = path.join(FIXTURES, 'deno-webapp', 'deno.lock');
      const result = await scanner.scan(path.join(FIXTURES, 'deno-webapp'), lockfilePath);

      expect(result.ecosystem).toBe('deno');
      // 2 JSR packages + 1 npm package = 3 total
      expect(result.dependencies.length).toBe(3);
    });

    it('identifies direct dependencies from deno.json', async () => {
      const lockfilePath = path.join(FIXTURES, 'deno-webapp', 'deno.lock');
      const result = await scanner.scan(path.join(FIXTURES, 'deno-webapp'), lockfilePath);

      const directDeps = result.dependencies.filter((d) => d.direct);
      const directNames = directDeps.map((d) => d.name).sort();

      expect(directNames).toContain('@std/path');
      expect(directNames).toContain('hono');
    });

    it('identifies transitive dependencies', async () => {
      const lockfilePath = path.join(FIXTURES, 'deno-webapp', 'deno.lock');
      const result = await scanner.scan(path.join(FIXTURES, 'deno-webapp'), lockfilePath);

      const transitiveDeps = result.dependencies.filter((d) => !d.direct);
      const transitiveNames = transitiveDeps.map((d) => d.name);

      expect(transitiveNames).toContain('@std/internal');
    });

    it('generates correct purls for v3 lockfile packages', async () => {
      const lockfilePath = path.join(FIXTURES, 'deno-webapp', 'deno.lock');
      const result = await scanner.scan(path.join(FIXTURES, 'deno-webapp'), lockfilePath);

      const stdPath = result.dependencies.find((d) => d.name === '@std/path');
      expect(stdPath?.purl).toBe('pkg:jsr/%40std%2Fpath@1.0.8');

      const hono = result.dependencies.find((d) => d.name === 'hono');
      expect(hono?.purl).toBe('pkg:npm/hono@4.6.20');
    });
  });
});
