import { describe, it, expect } from 'vitest';
import { NpmScanner } from '../../src/scanners/npm/npm-scanner.js';
import { LockfileParseError } from '../../src/core/errors.js';
import path from 'path';

const FIXTURES = path.resolve(__dirname, '../fixtures');

describe('NpmScanner', () => {
  const scanner = new NpmScanner();

  describe('detect()', () => {
    it('finds package-lock.json in a Node.js project', async () => {
      const result = await scanner.detect(path.join(FIXTURES, 'node-api'));
      expect(result).not.toBeNull();
      expect(result).toContain('package-lock.json');
    });

    it('returns null for a project with no lockfile', async () => {
      const result = await scanner.detect(path.join(FIXTURES, 'empty-project'));
      expect(result).toBeNull();
    });
  });

  describe('scan() — node-api fixture', () => {
    it('parses all dependencies from lockfile v3', async () => {
      const lockfilePath = path.join(FIXTURES, 'node-api', 'package-lock.json');
      const result = await scanner.scan(path.join(FIXTURES, 'node-api'), lockfilePath);

      expect(result.ecosystem).toBe('npm');
      expect(result.dependencies.length).toBeGreaterThan(0);

      // Should have our 5 direct deps
      const directDeps = result.dependencies.filter((d) => d.direct);
      const directNames = directDeps.map((d) => d.name).sort();
      expect(directNames).toEqual(['axios', 'express', 'jest', 'jsonwebtoken', 'lodash']);
    });

    it('includes transitive dependencies', async () => {
      const lockfilePath = path.join(FIXTURES, 'node-api', 'package-lock.json');
      const result = await scanner.scan(path.join(FIXTURES, 'node-api'), lockfilePath);

      const transitive = result.dependencies.filter((d) => !d.direct);
      expect(transitive.length).toBeGreaterThan(0);

      // body-parser, debug, ms, etc. are transitive
      const transitiveNames = transitive.map((d) => d.name);
      expect(transitiveNames).toContain('body-parser');
      expect(transitiveNames).toContain('debug');
      expect(transitiveNames).toContain('ms');
    });

    it('generates correct purls', async () => {
      const lockfilePath = path.join(FIXTURES, 'node-api', 'package-lock.json');
      const result = await scanner.scan(path.join(FIXTURES, 'node-api'), lockfilePath);

      const express = result.dependencies.find((d) => d.name === 'express');
      expect(express?.purl).toBe('pkg:npm/express@4.18.2');

      // Scoped package purl should encode the slash
      const typesNode = result.dependencies.find((d) => d.name === '@types/node');
      expect(typesNode?.purl).toBe('pkg:npm/%40types/node@20.11.5');
    });

    it('sets scannedAt timestamp', async () => {
      const lockfilePath = path.join(FIXTURES, 'node-api', 'package-lock.json');
      const result = await scanner.scan(path.join(FIXTURES, 'node-api'), lockfilePath);
      expect(result.scannedAt).toBeTruthy();
      expect(new Date(result.scannedAt).getTime()).not.toBeNaN();
    });
  });

  describe('scan() — vue-app fixture', () => {
    it('parses Vue project dependencies correctly', async () => {
      const lockfilePath = path.join(FIXTURES, 'vue-app', 'package-lock.json');
      const result = await scanner.scan(path.join(FIXTURES, 'vue-app'), lockfilePath);

      const names = result.dependencies.map((d) => d.name).sort();
      expect(names).toContain('vue');
      expect(names).toContain('pinia');
      expect(names).toContain('vue-router');
      expect(names).toContain('@vue/reactivity');
    });

    it('marks direct vs transitive correctly', async () => {
      const lockfilePath = path.join(FIXTURES, 'vue-app', 'package-lock.json');
      const result = await scanner.scan(path.join(FIXTURES, 'vue-app'), lockfilePath);

      const vue = result.dependencies.find((d) => d.name === 'vue');
      expect(vue?.direct).toBe(true);

      const reactivity = result.dependencies.find((d) => d.name === '@vue/reactivity');
      expect(reactivity?.direct).toBe(false);
    });
  });

  describe('scan() — react-app fixture', () => {
    it('handles a minimal React/Next.js project', async () => {
      const lockfilePath = path.join(FIXTURES, 'react-app', 'package-lock.json');
      const result = await scanner.scan(path.join(FIXTURES, 'react-app'), lockfilePath);

      expect(result.dependencies.length).toBe(3);
      expect(result.dependencies.every((d) => d.direct)).toBe(true);
    });
  });

  describe('scan() — lockfile v1 (legacy)', () => {
    it('parses legacy lockfile v1 format with nested dependencies', async () => {
      const lockfilePath = path.join(FIXTURES, 'node-legacy-v1', 'package-lock.json');
      const result = await scanner.scan(path.join(FIXTURES, 'node-legacy-v1'), lockfilePath);

      expect(result.ecosystem).toBe('npm');
      expect(result.dependencies.length).toBe(3);

      const names = result.dependencies.map((d) => d.name).sort();
      expect(names).toEqual(['debug', 'lodash', 'ms']);
    });

    it('correctly identifies direct vs transitive in v1 format', async () => {
      const lockfilePath = path.join(FIXTURES, 'node-legacy-v1', 'package-lock.json');
      const result = await scanner.scan(path.join(FIXTURES, 'node-legacy-v1'), lockfilePath);

      const lodash = result.dependencies.find((d) => d.name === 'lodash');
      const debug = result.dependencies.find((d) => d.name === 'debug');
      const ms = result.dependencies.find((d) => d.name === 'ms');

      expect(lodash?.direct).toBe(true);
      expect(debug?.direct).toBe(true);
      expect(ms?.direct).toBe(false); // nested under debug
    });

    it('generates correct purls for v1 lockfile', async () => {
      const lockfilePath = path.join(FIXTURES, 'node-legacy-v1', 'package-lock.json');
      const result = await scanner.scan(path.join(FIXTURES, 'node-legacy-v1'), lockfilePath);

      const lodash = result.dependencies.find((d) => d.name === 'lodash');
      expect(lodash?.purl).toBe('pkg:npm/lodash@4.17.21');
    });
  });

  describe('error handling', () => {
    it('throws LockfileParseError when lockfile contains invalid JSON', async () => {
      const lockfilePath = path.join(FIXTURES, 'node-invalid-lockfile', 'package-lock.json');

      await expect(
        scanner.scan(path.join(FIXTURES, 'node-invalid-lockfile'), lockfilePath)
      ).rejects.toThrow(LockfileParseError);

      await expect(
        scanner.scan(path.join(FIXTURES, 'node-invalid-lockfile'), lockfilePath)
      ).rejects.toThrow('Invalid JSON');
    });
  });

  describe('edge cases', () => {
    it('treats all dependencies as non-direct when package.json is missing', async () => {
      const lockfilePath = path.join(FIXTURES, 'node-no-packagejson', 'package-lock.json');
      const result = await scanner.scan(path.join(FIXTURES, 'node-no-packagejson'), lockfilePath);

      expect(result.dependencies.length).toBe(2); // express, body-parser
      // Without package.json, we can't determine direct deps
      expect(result.dependencies.every((d) => d.direct === false)).toBe(true);
    });

    it('skips workspace link entries (link: true)', async () => {
      const lockfilePath = path.join(FIXTURES, 'node-workspace-links', 'package-lock.json');
      const result = await scanner.scan(path.join(FIXTURES, 'node-workspace-links'), lockfilePath);

      // Should only have lodash, not @internal/utils (link: true)
      expect(result.dependencies.length).toBe(1);
      expect(result.dependencies[0].name).toBe('lodash');

      const internalUtils = result.dependencies.find((d) => d.name === '@internal/utils');
      expect(internalUtils).toBeUndefined();
    });
  });
});
