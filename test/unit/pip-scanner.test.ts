import { describe, it, expect } from 'vitest';
import { PipScanner } from '../../src/scanners/pip/pip-scanner.js';
import path from 'path';

const FIXTURES = path.resolve(__dirname, '../fixtures');

describe('PipScanner', () => {
  const scanner = new PipScanner();

  describe('detect()', () => {
    it('finds requirements.txt in a Python project', async () => {
      const result = await scanner.detect(path.join(FIXTURES, 'python-api'));
      expect(result).not.toBeNull();
      expect(result).toContain('requirements.txt');
    });

    it('finds Pipfile.lock in a Pipenv project', async () => {
      const result = await scanner.detect(path.join(FIXTURES, 'python-webapp'));
      expect(result).not.toBeNull();
      expect(result).toContain('Pipfile.lock');
    });

    it('returns null for a project with no Python files', async () => {
      const result = await scanner.detect(path.join(FIXTURES, 'empty-project'));
      expect(result).toBeNull();
    });

    it('returns null for an npm project', async () => {
      const result = await scanner.detect(path.join(FIXTURES, 'node-api'));
      expect(result).toBeNull();
    });
  });

  describe('scan() — python-api fixture (requirements.txt)', () => {
    it('parses all dependencies from requirements.txt', async () => {
      const lockfilePath = path.join(FIXTURES, 'python-api', 'requirements.txt');
      const result = await scanner.scan(path.join(FIXTURES, 'python-api'), lockfilePath);

      expect(result.ecosystem).toBe('pip');
      expect(result.dependencies.length).toBe(6);
    });

    it('extracts correct package names and versions', async () => {
      const lockfilePath = path.join(FIXTURES, 'python-api', 'requirements.txt');
      const result = await scanner.scan(path.join(FIXTURES, 'python-api'), lockfilePath);

      const flask = result.dependencies.find((d) => d.name === 'flask');
      expect(flask).toBeDefined();
      expect(flask?.version).toBe('3.0.0');

      const requests = result.dependencies.find((d) => d.name === 'requests');
      expect(requests).toBeDefined();
      expect(requests?.version).toBe('2.31.0');
    });

    it('normalizes package names per PEP 503', async () => {
      const lockfilePath = path.join(FIXTURES, 'python-api', 'requirements.txt');
      const result = await scanner.scan(path.join(FIXTURES, 'python-api'), lockfilePath);

      // python-dotenv should be normalized
      const dotenv = result.dependencies.find((d) => d.name === 'python-dotenv');
      expect(dotenv).toBeDefined();
      expect(dotenv?.version).toBe('1.0.0');
    });

    it('generates correct PyPI purls', async () => {
      const lockfilePath = path.join(FIXTURES, 'python-api', 'requirements.txt');
      const result = await scanner.scan(path.join(FIXTURES, 'python-api'), lockfilePath);

      const flask = result.dependencies.find((d) => d.name === 'flask');
      expect(flask?.purl).toBe('pkg:pypi/flask@3.0.0');

      const dotenv = result.dependencies.find((d) => d.name === 'python-dotenv');
      expect(dotenv?.purl).toBe('pkg:pypi/python-dotenv@1.0.0');
    });

    it('marks all requirements.txt deps as direct', async () => {
      const lockfilePath = path.join(FIXTURES, 'python-api', 'requirements.txt');
      const result = await scanner.scan(path.join(FIXTURES, 'python-api'), lockfilePath);

      expect(result.dependencies.every((d) => d.direct)).toBe(true);
    });

    it('skips comments and blank lines', async () => {
      const lockfilePath = path.join(FIXTURES, 'python-api', 'requirements.txt');
      const result = await scanner.scan(path.join(FIXTURES, 'python-api'), lockfilePath);

      // Should not include comment lines
      expect(result.dependencies.find((d) => d.name.startsWith('#'))).toBeUndefined();
    });

    it('sets scannedAt timestamp', async () => {
      const lockfilePath = path.join(FIXTURES, 'python-api', 'requirements.txt');
      const result = await scanner.scan(path.join(FIXTURES, 'python-api'), lockfilePath);
      expect(result.scannedAt).toBeTruthy();
      expect(new Date(result.scannedAt).getTime()).not.toBeNaN();
    });
  });

  describe('scan() — python-webapp fixture (Pipfile.lock)', () => {
    it('parses all dependencies from Pipfile.lock', async () => {
      const lockfilePath = path.join(FIXTURES, 'python-webapp', 'Pipfile.lock');
      const result = await scanner.scan(path.join(FIXTURES, 'python-webapp'), lockfilePath);

      expect(result.ecosystem).toBe('pip');
      // 9 default + 3 develop = 12
      expect(result.dependencies.length).toBe(12);
    });

    it('includes both default and develop dependencies', async () => {
      const lockfilePath = path.join(FIXTURES, 'python-webapp', 'Pipfile.lock');
      const result = await scanner.scan(path.join(FIXTURES, 'python-webapp'), lockfilePath);

      const names = result.dependencies.map((d) => d.name).sort();
      expect(names).toContain('django');
      expect(names).toContain('celery');
      expect(names).toContain('pytest');
      expect(names).toContain('coverage');
    });

    it('strips == prefix from Pipfile.lock versions', async () => {
      const lockfilePath = path.join(FIXTURES, 'python-webapp', 'Pipfile.lock');
      const result = await scanner.scan(path.join(FIXTURES, 'python-webapp'), lockfilePath);

      const django = result.dependencies.find((d) => d.name === 'django');
      expect(django?.version).toBe('5.0.1');

      const pytest = result.dependencies.find((d) => d.name === 'pytest');
      expect(pytest?.version).toBe('7.4.4');
    });

    it('normalizes hyphenated package names', async () => {
      const lockfilePath = path.join(FIXTURES, 'python-webapp', 'Pipfile.lock');
      const result = await scanner.scan(path.join(FIXTURES, 'python-webapp'), lockfilePath);

      // psycopg2-binary should be normalized
      const psycopg = result.dependencies.find((d) => d.name === 'psycopg2-binary');
      expect(psycopg).toBeDefined();

      // sentry-sdk should be normalized
      const sentry = result.dependencies.find((d) => d.name === 'sentry-sdk');
      expect(sentry).toBeDefined();
    });

    it('generates correct purls for Pipfile.lock packages', async () => {
      const lockfilePath = path.join(FIXTURES, 'python-webapp', 'Pipfile.lock');
      const result = await scanner.scan(path.join(FIXTURES, 'python-webapp'), lockfilePath);

      const django = result.dependencies.find((d) => d.name === 'django');
      expect(django?.purl).toBe('pkg:pypi/django@5.0.1');
    });
  });

  describe('scan() — -r includes support', () => {
    it('follows -r includes and parses all deps', async () => {
      const lockfilePath = path.join(FIXTURES, 'python-includes', 'requirements.txt');
      const result = await scanner.scan(path.join(FIXTURES, 'python-includes'), lockfilePath);

      // 2 from main + 3 from common.txt + 3 from dev/dev-requirements.txt = 8
      expect(result.dependencies.length).toBe(8);

      const names = result.dependencies.map((d) => d.name);
      // From main requirements.txt
      expect(names).toContain('flask');
      expect(names).toContain('requests');
      // From common.txt
      expect(names).toContain('sqlalchemy');
      expect(names).toContain('pydantic');
      expect(names).toContain('python-dotenv');
      // From dev/dev-requirements.txt
      expect(names).toContain('pytest');
      expect(names).toContain('coverage');
      expect(names).toContain('black');
    });

    it('handles nested directory includes', async () => {
      const lockfilePath = path.join(FIXTURES, 'python-includes', 'requirements.txt');
      const result = await scanner.scan(path.join(FIXTURES, 'python-includes'), lockfilePath);

      // dev/dev-requirements.txt should be included
      const pytest = result.dependencies.find((d) => d.name === 'pytest');
      expect(pytest).toBeDefined();
      expect(pytest?.version).toBe('7.4.4');
    });

    it('prevents infinite loops with circular includes', async () => {
      const lockfilePath = path.join(FIXTURES, 'python-circular', 'requirements.txt');
      const result = await scanner.scan(path.join(FIXTURES, 'python-circular'), lockfilePath);

      // Should parse without hanging: django + celery + redis = 3 unique deps
      expect(result.dependencies.length).toBe(3);

      const names = result.dependencies.map((d) => d.name);
      expect(names).toContain('django');
      expect(names).toContain('celery');
      expect(names).toContain('redis');
    });
  });

  describe('strict pinning enforcement', () => {
    it('throws LockfileParseError for >= version specifier', async () => {
      const lockfilePath = path.join(FIXTURES, 'python-unpinned', 'requirements.txt');
      await expect(
        scanner.scan(path.join(FIXTURES, 'python-unpinned'), lockfilePath)
      ).rejects.toThrow('Non-pinned dependency detected');
    });

    it('parses strictly pinned versions correctly', async () => {
      const lockfilePath = path.join(FIXTURES, 'python-includes', 'requirements.txt');
      const result = await scanner.scan(path.join(FIXTURES, 'python-includes'), lockfilePath);

      const requests = result.dependencies.find((d) => d.name === 'requests');
      expect(requests?.version).toBe('2.31.0');

      const sqlalchemy = result.dependencies.find((d) => d.name === 'sqlalchemy');
      expect(sqlalchemy?.version).toBe('2.0.25');

      const pydantic = result.dependencies.find((d) => d.name === 'pydantic');
      expect(pydantic?.version).toBe('2.5.0');
    });
  });
});
