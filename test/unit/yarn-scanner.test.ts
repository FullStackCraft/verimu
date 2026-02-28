import { describe, it, expect } from 'vitest';
import { YarnScanner } from '../../src/scanners/yarn/yarn-scanner.js';
import { LockfileParseError } from '../../src/core/errors.js';
import path from 'path';

const FIXTURES = path.resolve(__dirname, '../fixtures');

describe('YarnScanner', () => {
    const scanner = new YarnScanner();

    describe('detect()', () => {
        it('finds yarn.lock in a Yarn project', async () => {
            const result = await scanner.detect(path.join(FIXTURES, 'yarn-app'));
            expect(result).not.toBeNull();
            expect(result).toContain('yarn.lock');
        });

        it('returns null for a project with no yarn.lock', async () => {
            const result = await scanner.detect(path.join(FIXTURES, 'node-api'));
            expect(result).toBeNull();
        });
    });

    describe('scan() — yarn-app fixture', () => {
        it('parses all dependencies from yarn.lock', async () => {
            const lockfilePath = path.join(FIXTURES, 'yarn-app', 'yarn.lock');
            const result = await scanner.scan(path.join(FIXTURES, 'yarn-app'), lockfilePath);

            expect(result.ecosystem).toBe('npm');
            expect(result.dependencies.length).toBeGreaterThan(0);

            // Should have our 3 direct deps: express, lodash, @types/node
            const directDeps = result.dependencies.filter((d) => d.direct);
            const directNames = directDeps.map((d) => d.name).sort();
            expect(directNames).toEqual(['@types/node', 'express', 'lodash']);
        });

        it('includes transitive dependencies', async () => {
            const lockfilePath = path.join(FIXTURES, 'yarn-app', 'yarn.lock');
            const result = await scanner.scan(path.join(FIXTURES, 'yarn-app'), lockfilePath);

            const transitive = result.dependencies.filter((d) => !d.direct);
            expect(transitive.length).toBeGreaterThan(0);

            // body-parser, debug, ms, etc. are transitive
            const transitiveNames = transitive.map((d) => d.name);
            expect(transitiveNames).toContain('body-parser');
            expect(transitiveNames).toContain('debug');
            expect(transitiveNames).toContain('ms');
        });

        it('generates correct purls', async () => {
            const lockfilePath = path.join(FIXTURES, 'yarn-app', 'yarn.lock');
            const result = await scanner.scan(path.join(FIXTURES, 'yarn-app'), lockfilePath);

            const express = result.dependencies.find((d) => d.name === 'express');
            expect(express?.purl).toBe('pkg:npm/express@4.18.2');

            // Scoped package purl should encode the @ as %40
            const typesNode = result.dependencies.find((d) => d.name === '@types/node');
            expect(typesNode?.purl).toBe('pkg:npm/%40types/node@20.11.5');
        });

        it('sets scannedAt timestamp', async () => {
            const lockfilePath = path.join(FIXTURES, 'yarn-app', 'yarn.lock');
            const result = await scanner.scan(path.join(FIXTURES, 'yarn-app'), lockfilePath);
            expect(result.scannedAt).toBeTruthy();
            expect(new Date(result.scannedAt).getTime()).not.toBeNaN();
        });

        it('correctly parses express version', async () => {
            const lockfilePath = path.join(FIXTURES, 'yarn-app', 'yarn.lock');
            const result = await scanner.scan(path.join(FIXTURES, 'yarn-app'), lockfilePath);

            const express = result.dependencies.find((d) => d.name === 'express');
            expect(express?.version).toBe('4.18.2');
        });

        it('correctly parses lodash version', async () => {
            const lockfilePath = path.join(FIXTURES, 'yarn-app', 'yarn.lock');
            const result = await scanner.scan(path.join(FIXTURES, 'yarn-app'), lockfilePath);

            const lodash = result.dependencies.find((d) => d.name === 'lodash');
            expect(lodash?.version).toBe('4.17.21');
        });

        it('handles scoped packages correctly', async () => {
            const lockfilePath = path.join(FIXTURES, 'yarn-app', 'yarn.lock');
            const result = await scanner.scan(path.join(FIXTURES, 'yarn-app'), lockfilePath);

            const typesNode = result.dependencies.find((d) => d.name === '@types/node');
            expect(typesNode).toBeDefined();
            expect(typesNode?.name).toBe('@types/node');
            expect(typesNode?.version).toBe('20.11.5');
            expect(typesNode?.direct).toBe(true);
        });

        it('deduplicates packages with multiple version ranges', async () => {
            const lockfilePath = path.join(FIXTURES, 'yarn-app', 'yarn.lock');
            const result = await scanner.scan(path.join(FIXTURES, 'yarn-app'), lockfilePath);

            // ms appears multiple times in yarn.lock with different selectors
            const msVersions = result.dependencies.filter((d) => d.name === 'ms');
            const uniqueMsVersions = new Set(msVersions.map((d) => d.version));

            // Should have 2 unique versions of ms: 2.0.0 and 2.1.3
            expect(uniqueMsVersions.size).toBe(2);
            expect(Array.from(uniqueMsVersions).sort()).toEqual(['2.0.0', '2.1.3']);
        });

        it('sets ecosystem to npm (yarn uses npm registry)', async () => {
            const lockfilePath = path.join(FIXTURES, 'yarn-app', 'yarn.lock');
            const result = await scanner.scan(path.join(FIXTURES, 'yarn-app'), lockfilePath);

            expect(result.ecosystem).toBe('npm');
            expect(result.dependencies.every((d) => d.ecosystem === 'npm')).toBe(true);
        });
    });

    describe('lockfile parsing edge cases', () => {
        it('handles packages with range selectors in yarn.lock', async () => {
            const lockfilePath = path.join(FIXTURES, 'yarn-app', 'yarn.lock');
            const result = await scanner.scan(path.join(FIXTURES, 'yarn-app'), lockfilePath);

            // get-intrinsic has multiple selectors: ^1.0.2, ^1.1.3, ^1.2.1
            const getIntrinsic = result.dependencies.find((d) => d.name === 'get-intrinsic');
            expect(getIntrinsic).toBeDefined();
            expect(getIntrinsic?.version).toBe('1.2.2'); // All resolve to 1.2.2
        });

        it('handles packages with special characters in version ranges', async () => {
            const lockfilePath = path.join(FIXTURES, 'yarn-app', 'yarn.lock');
            const result = await scanner.scan(path.join(FIXTURES, 'yarn-app'), lockfilePath);

            // safer-buffer has ">= 2.1.2 < 3" version range
            const saferBuffer = result.dependencies.find((d) => d.name === 'safer-buffer');
            expect(saferBuffer).toBeDefined();
            expect(saferBuffer?.version).toBe('2.1.2');
        });
    });

    describe('ecosystem consistency', () => {
        it('uses npm ecosystem since yarn is an npm package manager', async () => {
            expect(scanner.ecosystem).toBe('npm');
        });

        it('identifies yarn.lock as the lockfile', async () => {
            expect(scanner.lockfileNames).toEqual(['yarn.lock']);
        });
    });

    describe('scan() — yarn-v2-app fixture (Berry format)', () => {
        it('detects and parses Yarn v2+ (Berry) lockfile format', async () => {
            const lockfilePath = path.join(FIXTURES, 'yarn-v2-app', 'yarn.lock');
            const result = await scanner.scan(path.join(FIXTURES, 'yarn-v2-app'), lockfilePath);

            expect(result.ecosystem).toBe('npm');
            expect(result.dependencies.length).toBeGreaterThan(0);
        });

        it('parses direct dependencies from v2+ lockfile', async () => {
            const lockfilePath = path.join(FIXTURES, 'yarn-v2-app', 'yarn.lock');
            const result = await scanner.scan(path.join(FIXTURES, 'yarn-v2-app'), lockfilePath);

            // Should have our 3 direct deps: express, lodash, @types/node
            const directDeps = result.dependencies.filter((d) => d.direct);
            const directNames = directDeps.map((d) => d.name).sort();
            expect(directNames).toEqual(['@types/node', 'express', 'lodash']);
        });

        it('includes transitive dependencies from v2+ lockfile', async () => {
            const lockfilePath = path.join(FIXTURES, 'yarn-v2-app', 'yarn.lock');
            const result = await scanner.scan(path.join(FIXTURES, 'yarn-v2-app'), lockfilePath);

            const transitive = result.dependencies.filter((d) => !d.direct);
            expect(transitive.length).toBeGreaterThan(0);

            // body-parser, debug, ms, etc. are transitive
            const transitiveNames = transitive.map((d) => d.name);
            expect(transitiveNames).toContain('body-parser');
            expect(transitiveNames).toContain('debug');
            expect(transitiveNames).toContain('ms');
        });

        it('generates correct purls for v2+ lockfile entries', async () => {
            const lockfilePath = path.join(FIXTURES, 'yarn-v2-app', 'yarn.lock');
            const result = await scanner.scan(path.join(FIXTURES, 'yarn-v2-app'), lockfilePath);

            const express = result.dependencies.find((d) => d.name === 'express');
            expect(express?.purl).toBe('pkg:npm/express@4.18.2');

            // Scoped package purl should encode the @ as %40
            const typesNode = result.dependencies.find((d) => d.name === '@types/node');
            expect(typesNode?.purl).toBe('pkg:npm/%40types/node@20.11.5');
        });

        it('correctly parses express version from v2+ lockfile', async () => {
            const lockfilePath = path.join(FIXTURES, 'yarn-v2-app', 'yarn.lock');
            const result = await scanner.scan(path.join(FIXTURES, 'yarn-v2-app'), lockfilePath);

            const express = result.dependencies.find((d) => d.name === 'express');
            expect(express?.version).toBe('4.18.2');
        });

        it('correctly parses lodash version from v2+ lockfile', async () => {
            const lockfilePath = path.join(FIXTURES, 'yarn-v2-app', 'yarn.lock');
            const result = await scanner.scan(path.join(FIXTURES, 'yarn-v2-app'), lockfilePath);

            const lodash = result.dependencies.find((d) => d.name === 'lodash');
            expect(lodash?.version).toBe('4.17.21');
        });

        it('handles scoped packages in v2+ lockfile correctly', async () => {
            const lockfilePath = path.join(FIXTURES, 'yarn-v2-app', 'yarn.lock');
            const result = await scanner.scan(path.join(FIXTURES, 'yarn-v2-app'), lockfilePath);

            const typesNode = result.dependencies.find((d) => d.name === '@types/node');
            expect(typesNode).toBeDefined();
            expect(typesNode?.name).toBe('@types/node');
            expect(typesNode?.version).toBe('20.11.5');
            expect(typesNode?.direct).toBe(true);
        });

        it('deduplicates packages with same version in v2+ lockfile', async () => {
            const lockfilePath = path.join(FIXTURES, 'yarn-v2-app', 'yarn.lock');
            const result = await scanner.scan(path.join(FIXTURES, 'yarn-v2-app'), lockfilePath);

            // Should only have one entry per package@version
            const msVersions = result.dependencies.filter((d) => d.name === 'ms');
            const uniqueMsVersions = new Set(msVersions.map((d) => d.version));

            // Should have only 1 unique version of ms: 2.0.0
            expect(uniqueMsVersions.size).toBe(1);
            expect(Array.from(uniqueMsVersions)).toEqual(['2.0.0']);
        });

        it('sets ecosystem to npm for v2+ lockfile (yarn uses npm registry)', async () => {
            const lockfilePath = path.join(FIXTURES, 'yarn-v2-app', 'yarn.lock');
            const result = await scanner.scan(path.join(FIXTURES, 'yarn-v2-app'), lockfilePath);

            expect(result.ecosystem).toBe('npm');
            expect(result.dependencies.every((d) => d.ecosystem === 'npm')).toBe(true);
        });

        it('skips __metadata and workspace entries in v2+ lockfile', async () => {
            const lockfilePath = path.join(FIXTURES, 'yarn-v2-app', 'yarn.lock');
            const result = await scanner.scan(path.join(FIXTURES, 'yarn-v2-app'), lockfilePath);

            // __metadata should not appear as a dependency
            const metadataEntry = result.dependencies.find((d) => d.name === '__metadata');
            expect(metadataEntry).toBeUndefined();

            // workspace: entries should not appear
            const workspaceEntry = result.dependencies.find((d) => d.name?.includes('@workspace'));
            expect(workspaceEntry).toBeUndefined();
        });

        it('correctly handles aliased packages using resolution field', async () => {
            const lockfilePath = path.join(FIXTURES, 'yarn-v2-app', 'yarn.lock');
            const result = await scanner.scan(path.join(FIXTURES, 'yarn-v2-app'), lockfilePath);

            // lodash-es@npm:lodash@^4.17.21 should resolve to "lodash", not "lodash-es"
            // This tests that we extract name from resolution field, not the key
            const lodashDeps = result.dependencies.filter((d) => d.version === '4.17.21');

            // All should be named "lodash", not "lodash-es"
            for (const dep of lodashDeps) {
                expect(dep.name).toBe('lodash');
            }

            // Should not find any dependency named "lodash-es"
            const lodashEsDep = result.dependencies.find((d) => d.name === 'lodash-es');
            expect(lodashEsDep).toBeUndefined();
        });

        it('explicitly skips workspace packages', async () => {
            const lockfilePath = path.join(FIXTURES, 'yarn-v2-app', 'yarn.lock');
            const result = await scanner.scan(path.join(FIXTURES, 'yarn-v2-app'), lockfilePath);

            // my-lib@workspace:* should not appear in dependencies
            const workspaceDep = result.dependencies.find((d) => d.name === 'my-lib');
            expect(workspaceDep).toBeUndefined();
        });
    });

    describe('error handling', () => {
        it('throws LockfileParseError on invalid YAML in v2+ lockfile', async () => {
            const lockfilePath = path.join(FIXTURES, 'yarn-invalid-lockfile', 'yarn.lock');

            await expect(
                scanner.scan(path.join(FIXTURES, 'yarn-invalid-lockfile'), lockfilePath)
            ).rejects.toThrow(LockfileParseError);
        });

        it('includes helpful error message on parse failure', async () => {
            const lockfilePath = path.join(FIXTURES, 'yarn-invalid-lockfile', 'yarn.lock');

            try {
                await scanner.scan(path.join(FIXTURES, 'yarn-invalid-lockfile'), lockfilePath);
                expect.fail('Should have thrown LockfileParseError');
            } catch (err) {
                expect(err).toBeInstanceOf(LockfileParseError);
                expect((err as Error).message).toContain('Failed to parse yarn.lock');
            }
        });
    });

    describe('edge cases', () => {
        it('marks all dependencies as non-direct when package.json is missing', async () => {
            const lockfilePath = path.join(FIXTURES, 'yarn-no-packagejson', 'yarn.lock');
            const result = await scanner.scan(path.join(FIXTURES, 'yarn-no-packagejson'), lockfilePath);

            expect(result.dependencies.length).toBeGreaterThan(0);

            // All dependencies should be marked as non-direct when package.json is missing
            const allNonDirect = result.dependencies.every((d) => !d.direct);
            expect(allNonDirect).toBe(true);
        });

        it('handles v2+ lockfile without package.json gracefully', async () => {
            const lockfilePath = path.join(FIXTURES, 'yarn-no-packagejson', 'yarn.lock');
            const result = await scanner.scan(path.join(FIXTURES, 'yarn-no-packagejson'), lockfilePath);

            // Should still parse dependencies correctly
            expect(result.ecosystem).toBe('npm');
            expect(result.dependencies.length).toBe(2); // express and lodash

            const express = result.dependencies.find((d) => d.name === 'express');
            const lodash = result.dependencies.find((d) => d.name === 'lodash');

            expect(express?.version).toBe('4.18.2');
            expect(lodash?.version).toBe('4.17.21');
        });
    });
});
