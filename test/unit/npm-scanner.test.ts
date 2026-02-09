import { describe, it, expect } from 'vitest';
import { NpmScanner } from '../../src/scanners/npm/npm-scanner.js';
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
});
