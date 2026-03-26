import { describe, it, expect } from 'vitest';
import path from 'path';
import { LockfileDiscovery } from '../../src/discovery/lockfile-discovery.js';

const FIXTURES = path.resolve(__dirname, '../fixtures/recursive-discovery');

describe('LockfileDiscovery', () => {
  const discovery = new LockfileDiscovery();

  describe('discover()', () => {
    it('finds all projects in a multi-ecosystem directory tree', async () => {
      const results = await discovery.discover({
        rootPath: path.join(FIXTURES, 'multi-ecosystem'),
      });

      expect(results.length).toBe(2);

      const scannerTypes = results.map(r => r.scannerType).sort();
      expect(scannerTypes).toEqual(['cargo', 'npm']);

      // Verify paths (normalize for cross-platform compatibility)
      const relativePaths = results.map(r => r.relativePath.replace(/\\/g, '/')).sort();
      expect(relativePaths).toContain('frontend');
      expect(relativePaths).toContain('services/api');
    });

    it('respects exclude patterns', async () => {
      const results = await discovery.discover({
        rootPath: path.join(FIXTURES, 'with-excludes'),
        exclude: ['legacy/**', 'legacy'],
      });

      expect(results.length).toBe(1);
      expect(results[0].relativePath).toBe('active');
    });

    it('returns empty array for directory with no lockfiles', async () => {
      const results = await discovery.discover({
        rootPath: path.join(FIXTURES, 'non-existent-dir-12345'),
      });

      expect(results).toEqual([]);
    });

    it('identifies correct ecosystem and scanner for npm projects', async () => {
      const results = await discovery.discover({
        rootPath: path.join(FIXTURES, 'with-excludes/active'),
      });

      expect(results.length).toBe(1);
      expect(results[0].ecosystem).toBe('npm');
      expect(results[0].scannerType).toBe('npm');
      expect(results[0].lockfile.name).toBe('package-lock.json');
    });

    it('identifies correct ecosystem and scanner for cargo projects', async () => {
      const results = await discovery.discover({
        rootPath: path.join(FIXTURES, 'multi-ecosystem/services/api'),
      });

      expect(results.length).toBe(1);
      expect(results[0].ecosystem).toBe('cargo');
      expect(results[0].scannerType).toBe('cargo');
      expect(results[0].lockfile.name).toBe('Cargo.lock');
    });

    it('stops at first lockfile found (does not descend into subdirs)', async () => {
      // If we scan from root, it should find projects and not descend further
      const results = await discovery.discover({
        rootPath: path.join(FIXTURES, 'multi-ecosystem'),
      });

      // Should find frontend and services/api, but not descend into their subdirs
      expect(results.length).toBe(2);
    });
  });

  describe('glob matching for exclude patterns', () => {
    it('matches single wildcard exclude patterns', async () => {
      const results = await discovery.discover({
        rootPath: path.join(FIXTURES, 'with-excludes'),
        exclude: ['legacy'],
      });

      expect(results.length).toBe(1);
      expect(results[0].relativePath).toBe('active');
    });

    it('matches double wildcard exclude patterns', async () => {
      const results = await discovery.discover({
        rootPath: path.join(FIXTURES, 'with-excludes'),
        exclude: ['legacy', 'legacy/**'],
      });

      expect(results.length).toBe(1);
      expect(results[0].relativePath).toBe('active');
    });
  });
});
