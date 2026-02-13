import { describe, it, expect } from 'vitest';
import path from 'path';
import { ComposerScanner } from '../../src/scanners/composer/composer-scanner.js';

const FIXTURES = path.resolve(__dirname, '../fixtures');

describe('ComposerScanner', () => {
  const scanner = new ComposerScanner();

  describe('detect()', () => {
    it('finds composer.lock in a PHP project', async () => {
      const result = await scanner.detect(path.join(FIXTURES, 'php-api'));
      expect(result).not.toBeNull();
      expect(result).toContain('composer.lock');
    });

    it('returns null for a project without composer.lock', async () => {
      const result = await scanner.detect(path.join(FIXTURES, 'node-api'));
      expect(result).toBeNull();
    });
  });

  describe('scan()', () => {
    it('parses all dependencies from composer.lock', async () => {
      const lockfilePath = path.join(FIXTURES, 'php-api', 'composer.lock');
      const result = await scanner.scan(path.join(FIXTURES, 'php-api'), lockfilePath);

      expect(result.ecosystem).toBe('composer');
      expect(result.dependencies.length).toBe(3);
      expect(result.dependencies.every((dep) => dep.ecosystem === 'composer')).toBe(true);
    });

    it('identifies direct and transitive dependencies from composer.json', async () => {
      const lockfilePath = path.join(FIXTURES, 'php-api', 'composer.lock');
      const result = await scanner.scan(path.join(FIXTURES, 'php-api'), lockfilePath);

      const laravel = result.dependencies.find((dep) => dep.name === 'laravel/framework');
      const phpunit = result.dependencies.find((dep) => dep.name === 'phpunit/phpunit');
      const guzzle = result.dependencies.find((dep) => dep.name === 'guzzlehttp/guzzle');

      expect(laravel?.direct).toBe(true);
      expect(phpunit?.direct).toBe(true);
      expect(guzzle?.direct).toBe(false);
    });

    it('generates composer purls', async () => {
      const lockfilePath = path.join(FIXTURES, 'php-api', 'composer.lock');
      const result = await scanner.scan(path.join(FIXTURES, 'php-api'), lockfilePath);

      const laravel = result.dependencies.find((dep) => dep.name === 'laravel/framework');
      expect(laravel?.purl).toBe('pkg:composer/laravel/framework@v10.48.8');
    });
  });
});

