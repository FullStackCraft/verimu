import { describe, it, expect } from 'vitest';
import { PnpmScanner } from '../../src/scanners/pnpm/pnpm-scanner.js';
import { LockfileParseError } from '../../src/core/errors.js';
import path from 'path';

const FIXTURES = path.resolve(__dirname, '../fixtures');

describe('PnpmScanner', () => {
    const scanner = new PnpmScanner();

    describe('detect()', () => {
        it('finds pnpm-lock.yaml in a pnpm project', async () => {
            const result = await scanner.detect(path.join(FIXTURES, 'pnpm-app'));
            expect(result).not.toBeNull();
            expect(result).toContain('pnpm-lock.yaml');
        });

        it('returns null for a project with no pnpm-lock.yaml', async () => {
            const result = await scanner.detect(path.join(FIXTURES, 'node-api'));
            expect(result).toBeNull();
        });
    });

    describe('scan() — pnpm-app fixture', () => {
        it('parses all dependencies from pnpm-lock.yaml', async () => {
            const lockfilePath = path.join(FIXTURES, 'pnpm-app', 'pnpm-lock.yaml');
            const result = await scanner.scan(path.join(FIXTURES, 'pnpm-app'), lockfilePath);

            expect(result.ecosystem).toBe('npm');
            expect(result.dependencies.length).toBeGreaterThan(0);

            // Should have our 3 direct deps: express, lodash, @types/node
            const directDeps = result.dependencies.filter((d) => d.direct);
            const directNames = directDeps.map((d) => d.name).sort();
            expect(directNames).toEqual(['@types/node', 'express', 'lodash']);
        });

        it('includes transitive dependencies', async () => {
            const lockfilePath = path.join(FIXTURES, 'pnpm-app', 'pnpm-lock.yaml');
            const result = await scanner.scan(path.join(FIXTURES, 'pnpm-app'), lockfilePath);

            const transitive = result.dependencies.filter((d) => !d.direct);
            expect(transitive.length).toBeGreaterThan(0);

            // body-parser, debug, ms, etc. are transitive
            const transitiveNames = transitive.map((d) => d.name);
            expect(transitiveNames).toContain('body-parser');
            expect(transitiveNames).toContain('debug');
            expect(transitiveNames).toContain('ms');
        });

        it('generates correct purls', async () => {
            const lockfilePath = path.join(FIXTURES, 'pnpm-app', 'pnpm-lock.yaml');
            const result = await scanner.scan(path.join(FIXTURES, 'pnpm-app'), lockfilePath);

            const express = result.dependencies.find((d) => d.name === 'express');
            expect(express?.purl).toBe('pkg:npm/express@4.18.2');

            // Scoped package purl should encode the @ as %40
            const typesNode = result.dependencies.find((d) => d.name === '@types/node');
            expect(typesNode?.purl).toBe('pkg:npm/%40types/node@20.11.5');
        });

        it('sets scannedAt timestamp', async () => {
            const lockfilePath = path.join(FIXTURES, 'pnpm-app', 'pnpm-lock.yaml');
            const result = await scanner.scan(path.join(FIXTURES, 'pnpm-app'), lockfilePath);
            expect(result.scannedAt).toBeTruthy();
            expect(new Date(result.scannedAt).getTime()).not.toBeNaN();
        });

        it('correctly parses express version', async () => {
            const lockfilePath = path.join(FIXTURES, 'pnpm-app', 'pnpm-lock.yaml');
            const result = await scanner.scan(path.join(FIXTURES, 'pnpm-app'), lockfilePath);

            const express = result.dependencies.find((d) => d.name === 'express');
            expect(express?.version).toBe('4.18.2');
        });

        it('correctly parses lodash version', async () => {
            const lockfilePath = path.join(FIXTURES, 'pnpm-app', 'pnpm-lock.yaml');
            const result = await scanner.scan(path.join(FIXTURES, 'pnpm-app'), lockfilePath);

            const lodash = result.dependencies.find((d) => d.name === 'lodash');
            expect(lodash?.version).toBe('4.17.21');
        });

        it('handles scoped packages correctly', async () => {
            const lockfilePath = path.join(FIXTURES, 'pnpm-app', 'pnpm-lock.yaml');
            const result = await scanner.scan(path.join(FIXTURES, 'pnpm-app'), lockfilePath);

            const typesNode = result.dependencies.find((d) => d.name === '@types/node');
            expect(typesNode).toBeDefined();
            expect(typesNode?.name).toBe('@types/node');
            expect(typesNode?.version).toBe('20.11.5');
            expect(typesNode?.direct).toBe(true);
        });

        it('deduplicates packages', async () => {
            const lockfilePath = path.join(FIXTURES, 'pnpm-app', 'pnpm-lock.yaml');
            const result = await scanner.scan(path.join(FIXTURES, 'pnpm-app'), lockfilePath);

            // Count occurrences of each package
            const counts = new Map<string, number>();
            for (const dep of result.dependencies) {
                const key = `${dep.name}@${dep.version}`;
                counts.set(key, (counts.get(key) || 0) + 1);
            }

            // All packages should appear exactly once
            for (const [key, count] of counts.entries()) {
                expect(count).toBe(1);
            }
        });
    });

    describe('scan() — pnpm v6+ format (importers section)', () => {
        it('correctly detects direct dependencies from importers section', async () => {
            const lockfilePath = path.join(FIXTURES, 'pnpm-v6-app', 'pnpm-lock.yaml');
            const result = await scanner.scan(
                path.join(FIXTURES, 'pnpm-v6-app'),
                lockfilePath
            );

            expect(result.ecosystem).toBe('npm');
            expect(result.dependencies.length).toBeGreaterThan(0);

            // Direct dependencies should be detected from importers['.'] section
            const directDeps = result.dependencies.filter((d) => d.direct);
            expect(directDeps.length).toBeGreaterThan(0);

            // express and lodash should be marked as direct (from importers['.'].dependencies)
            const express = result.dependencies.find((d) => d.name === 'express');
            expect(express?.direct).toBe(true);
            expect(express?.version).toBe('4.18.2');

            const lodash = result.dependencies.find((d) => d.name === 'lodash');
            expect(lodash?.direct).toBe(true);
            expect(lodash?.version).toBe('4.17.21');

            // @types/node should be marked as direct (from importers['.'].devDependencies)
            const typesNode = result.dependencies.find((d) => d.name === '@types/node');
            expect(typesNode?.direct).toBe(true);
            expect(typesNode?.version).toBe('20.11.5');

            // Transitive dependencies should not be marked as direct
            const bodyParser = result.dependencies.find((d) => d.name === 'body-parser');
            expect(bodyParser?.direct).toBe(false);
        });
    });

    describe('workspace filtering', () => {
        it('filters out workspace packages', async () => {
            const lockfilePath = path.join(FIXTURES, 'pnpm-workspace', 'pnpm-lock.yaml');
            const result = await scanner.scan(
                path.join(FIXTURES, 'pnpm-workspace'),
                lockfilePath
            );

            // Should not include any workspace packages
            const workspacePackages = result.dependencies.filter((d) =>
                d.name.includes('workspace') || d.version.includes('workspace')
            );
            expect(workspacePackages.length).toBe(0);

            // Should still have regular packages
            expect(result.dependencies.length).toBeGreaterThan(0);
            const express = result.dependencies.find((d) => d.name === 'express');
            expect(express).toBeDefined();
        });
    });

    describe('error handling', () => {
        it('throws LockfileParseError for invalid YAML', async () => {
            const lockfilePath = path.join(FIXTURES, 'pnpm-invalid-lockfile', 'pnpm-lock.yaml');
            await expect(
                scanner.scan(path.join(FIXTURES, 'pnpm-invalid-lockfile'), lockfilePath)
            ).rejects.toThrow(LockfileParseError);
        });
    });
});
