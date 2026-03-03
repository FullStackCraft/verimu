import { describe, it, expect } from 'vitest';
import { UvScanner } from '../../src/scanners/uv/uv-scanner.js';
import path from 'path';

const FIXTURES = path.resolve(__dirname, '../fixtures');

describe('UvScanner', () => {
    const scanner = new UvScanner();

    describe('detect()', () => {
        it('finds uv.lock in a UV project', async () => {
            const result = await scanner.detect(path.join(FIXTURES, 'uv-webapp'));
            expect(result).not.toBeNull();
            expect(result).toContain('uv.lock');
        });

        it('returns null for a project with no uv.lock', async () => {
            const result = await scanner.detect(path.join(FIXTURES, 'empty-project'));
            expect(result).toBeNull();
        });

        it('returns null for a pip project', async () => {
            const result = await scanner.detect(path.join(FIXTURES, 'python-api'));
            expect(result).toBeNull();
        });

        it('returns null for an npm project', async () => {
            const result = await scanner.detect(path.join(FIXTURES, 'node-api'));
            expect(result).toBeNull();
        });
    });

    describe('scan() — uv-webapp fixture (uv.lock + pyproject.toml)', () => {
        it('parses all dependencies from uv.lock, excluding root project', async () => {
            const lockfilePath = path.join(FIXTURES, 'uv-webapp', 'uv.lock');
            const result = await scanner.scan(path.join(FIXTURES, 'uv-webapp'), lockfilePath);

            expect(result.ecosystem).toBe('uv');
            // 12 packages total, minus 1 root (uv-webapp) = 11
            expect(result.dependencies.length).toBe(11);

            // Root project should NOT be in the list
            const root = result.dependencies.find((d) => d.name === 'uv-webapp');
            expect(root).toBeUndefined();
        });

        it('extracts correct package names and versions', async () => {
            const lockfilePath = path.join(FIXTURES, 'uv-webapp', 'uv.lock');
            const result = await scanner.scan(path.join(FIXTURES, 'uv-webapp'), lockfilePath);

            const django = result.dependencies.find((d) => d.name === 'django');
            expect(django).toBeDefined();
            expect(django?.version).toBe('5.0.1');

            const celery = result.dependencies.find((d) => d.name === 'celery');
            expect(celery).toBeDefined();
            expect(celery?.version).toBe('5.3.6');
        });

        it('distinguishes direct vs transitive dependencies', async () => {
            const lockfilePath = path.join(FIXTURES, 'uv-webapp', 'uv.lock');
            const result = await scanner.scan(path.join(FIXTURES, 'uv-webapp'), lockfilePath);

            // Direct dependencies from pyproject.toml
            const django = result.dependencies.find((d) => d.name === 'django');
            expect(django?.direct).toBe(true);

            const pytest = result.dependencies.find((d) => d.name === 'pytest');
            expect(pytest?.direct).toBe(true);

            // Transitive dependencies (not in pyproject.toml)
            const asgiref = result.dependencies.find((d) => d.name === 'asgiref');
            expect(asgiref?.direct).toBe(false);

            const sqlparse = result.dependencies.find((d) => d.name === 'sqlparse');
            expect(sqlparse?.direct).toBe(false);
        });

        it('normalizes package names per PEP 503', async () => {
            const lockfilePath = path.join(FIXTURES, 'uv-webapp', 'uv.lock');
            const result = await scanner.scan(path.join(FIXTURES, 'uv-webapp'), lockfilePath);

            const psycopg = result.dependencies.find((d) => d.name === 'psycopg2-binary');
            expect(psycopg).toBeDefined();

            const sentry = result.dependencies.find((d) => d.name === 'sentry-sdk');
            expect(sentry).toBeDefined();
        });

        it('generates correct PyPI purls', async () => {
            const lockfilePath = path.join(FIXTURES, 'uv-webapp', 'uv.lock');
            const result = await scanner.scan(path.join(FIXTURES, 'uv-webapp'), lockfilePath);

            const django = result.dependencies.find((d) => d.name === 'django');
            expect(django?.purl).toBe('pkg:pypi/django@5.0.1');

            const sentry = result.dependencies.find((d) => d.name === 'sentry-sdk');
            expect(sentry?.purl).toBe('pkg:pypi/sentry-sdk@1.39.1');
        });

        it('sets scannedAt timestamp', async () => {
            const lockfilePath = path.join(FIXTURES, 'uv-webapp', 'uv.lock');
            const result = await scanner.scan(path.join(FIXTURES, 'uv-webapp'), lockfilePath);
            expect(result.scannedAt).toBeTruthy();
            expect(new Date(result.scannedAt).getTime()).not.toBeNaN();
        });
    });

    describe('scan() — uv-api fixture (uv.lock only, no pyproject.toml)', () => {
        it('parses all dependencies', async () => {
            const lockfilePath = path.join(FIXTURES, 'uv-api', 'uv.lock');
            const result = await scanner.scan(path.join(FIXTURES, 'uv-api'), lockfilePath);

            expect(result.ecosystem).toBe('uv');
            expect(result.dependencies.length).toBe(5);
        });

        it('marks all deps as direct when pyproject.toml is absent', async () => {
            const lockfilePath = path.join(FIXTURES, 'uv-api', 'uv.lock');
            const result = await scanner.scan(path.join(FIXTURES, 'uv-api'), lockfilePath);

            expect(result.dependencies.every((d) => d.direct)).toBe(true);
        });

        it('extracts correct names and versions', async () => {
            const lockfilePath = path.join(FIXTURES, 'uv-api', 'uv.lock');
            const result = await scanner.scan(path.join(FIXTURES, 'uv-api'), lockfilePath);

            const flask = result.dependencies.find((d) => d.name === 'flask');
            expect(flask).toBeDefined();
            expect(flask?.version).toBe('3.0.0');

            const dotenv = result.dependencies.find((d) => d.name === 'python-dotenv');
            expect(dotenv).toBeDefined();
            expect(dotenv?.version).toBe('1.0.0');
        });
    });
});
