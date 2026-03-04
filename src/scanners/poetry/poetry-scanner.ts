import { readFile } from 'fs/promises';
import { existsSync } from 'fs';
import path from 'path';
import type { DependencyScanner } from '../scanner.interface.js';
import type { Dependency, Ecosystem, ScanResult } from '../../core/types.js';
import { LockfileParseError } from '../../core/errors.js';

/**
 * Python / Poetry dependency scanner.
 *
 * Parses `poetry.lock` (TOML format) to extract the full resolved
 * dependency tree. Reads `pyproject.toml` to determine which packages
 * are direct dependencies vs transitive.
 *
 * poetry.lock format:
 * ```toml
 * [[package]]
 * name = "requests"
 * version = "2.31.0"
 * description = "Python HTTP for Humans."
 * optional = false
 * python-versions = ">=3.8"
 * ```
 *
 * Direct dependencies are identified by parsing the `[tool.poetry.dependencies]`
 * and `[tool.poetry.group.*.dependencies]` sections of `pyproject.toml`.
 *
 * Note: Uses a simple TOML parser since poetry.lock has a very
 * regular structure (just [[package]] entries). No need for a full
 * TOML library.
 */
export class PoetryScanner implements DependencyScanner {
    readonly ecosystem: Ecosystem = 'poetry';
    readonly lockfileNames = ['poetry.lock'];

    async detect(projectPath: string): Promise<string | null> {
        const lockfilePath = path.join(projectPath, 'poetry.lock');
        return existsSync(lockfilePath) ? lockfilePath : null;
    }

    async scan(projectPath: string, lockfilePath: string): Promise<ScanResult> {
        const [lockfileRaw, pyprojectRaw] = await Promise.all([
            readFile(lockfilePath, 'utf-8'),
            readFile(path.join(projectPath, 'pyproject.toml'), 'utf-8').catch(() => null),
        ]);

        const packages = this.parseLockfile(lockfileRaw, lockfilePath);
        const directNames = pyprojectRaw ? this.parsePyprojectToml(pyprojectRaw) : new Set<string>();

        const dependencies: Dependency[] = [];
        for (const pkg of packages) {
            dependencies.push({
                name: this.normalizePipName(pkg.name),
                version: pkg.version,
                direct: directNames.size > 0 ? directNames.has(this.normalizePipName(pkg.name)) : true,
                ecosystem: 'poetry',
                purl: this.buildPurl(pkg.name, pkg.version),
            });
        }

        return {
            projectPath,
            ecosystem: 'poetry',
            dependencies,
            lockfilePath,
            scannedAt: new Date().toISOString(),
        };
    }

    /**
     * Parses poetry.lock by splitting on [[package]] blocks.
     * Lightweight parser that handles the regular structure
     * without needing a full TOML library.
     */
    private parseLockfile(content: string, lockfilePath: string): PoetryPackage[] {
        const packages: PoetryPackage[] = [];
        const blocks = content.split(/^\[\[package\]\]$/m);

        for (const block of blocks) {
            if (!block.trim()) continue;

            const name = this.extractField(block, 'name');
            const version = this.extractField(block, 'version');

            if (name && version) {
                packages.push({ name, version });
            }
        }

        if (packages.length === 0 && content.includes('[[package]]')) {
            throw new LockfileParseError(lockfilePath, 'Failed to parse any packages from poetry.lock');
        }

        return packages;
    }

    /**
     * Extracts a string field value from a TOML block.
     * Handles: `name = "value"` format.
     */
    private extractField(block: string, fieldName: string): string | null {
        const regex = new RegExp(`^${fieldName}\\s*=\\s*"([^"]*)"`, 'm');
        const match = block.match(regex);
        return match ? match[1] : null;
    }

    /**
     * Parses `pyproject.toml` to extract direct dependency names.
     *
     * Looks for:
     *   - `[tool.poetry.dependencies]` — main dependencies
     *   - `[tool.poetry.group.dev.dependencies]` — dev dependencies
     *   - `[tool.poetry.group.*.dependencies]` — other groups
     *
     * Supports formats:
     *   - `requests = "^2.31.0"`
     *   - `requests = { version = "^2.31.0", optional = true }`
     *   - `python = "^3.12"` — skipped (the Python interpreter itself)
     */
    private parsePyprojectToml(content: string): Set<string> {
        const directNames = new Set<string>();
        let inDepsSection = false;

        for (const rawLine of content.split('\n')) {
            const line = rawLine.trim();

            // Detect section headers
            if (line.startsWith('[')) {
                inDepsSection =
                    line === '[tool.poetry.dependencies]' ||
                    /^\[tool\.poetry\.group\.[^\]]+\.dependencies\]$/.test(line);
                continue;
            }

            if (inDepsSection && line && !line.startsWith('#')) {
                // Extract package name from "name = ..." lines
                const match = line.match(/^([a-zA-Z0-9_][a-zA-Z0-9._-]*)\s*=/);
                if (match && match[1]) {
                    const name = this.normalizePipName(match[1]);
                    // Skip the python version constraint
                    if (name !== 'python') {
                        directNames.add(name);
                    }
                }
            }
        }

        return directNames;
    }

    /**
     * Normalizes a pip package name per PEP 503.
     * Converts to lowercase and replaces any run of [-_.] with a single hyphen.
     */
    private normalizePipName(name: string): string {
        return name.toLowerCase().replace(/[-_.]+/g, '-');
    }

    /**
     * Builds a purl for a PyPI package.
     * Per purl spec, the type is "pypi" (not "poetry").
     */
    private buildPurl(name: string, version: string): string {
        return `pkg:pypi/${this.normalizePipName(name)}@${version}`;
    }
}

// ─── Internal types ──────────────────────────────────────────────

interface PoetryPackage {
    name: string;
    version: string;
}
