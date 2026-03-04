import { readFile } from 'fs/promises';
import { existsSync } from 'fs';
import path from 'path';
import type { DependencyScanner } from '../scanner.interface.js';
import type { Dependency, Ecosystem, ScanResult } from '../../core/types.js';
import { LockfileParseError } from '../../core/errors.js';

/**
 * Python / UV dependency scanner.
 *
 * Parses `uv.lock` to extract the full resolved dependency tree.
 * Reads `pyproject.toml` to determine which packages are direct
 * dependencies vs transitive.
 *
 * uv.lock format:
 * ```toml
 * version = 1
 * requires-python = ">=3.12"
 *
 * [[package]]
 * name = "requests"
 * version = "2.31.0"
 * source = { registry = "https://pypi.org/simple" }
 * dependencies = [
 *     { name = "certifi" },
 *     { name = "charset-normalizer" },
 * ]
 * ```
 *
 * The root project is typically included as a `[[package]]` entry
 * without a `source` field (or with `source = { editable = "." }`).
 * It is excluded from the dependency list.
 *
 * Note: Uses a simple TOML parser since uv.lock has a very
 * regular structure. No need for a full TOML library.
 */
export class UvScanner implements DependencyScanner {
    readonly ecosystem: Ecosystem = 'uv';
    readonly lockfileNames = ['uv.lock'];

    async detect(projectPath: string): Promise<string | null> {
        const lockfilePath = path.join(projectPath, 'uv.lock');
        return existsSync(lockfilePath) ? lockfilePath : null;
    }

    async scan(projectPath: string, lockfilePath: string): Promise<ScanResult> {
        const [lockfileRaw, pyprojectRaw] = await Promise.all([
            readFile(lockfilePath, 'utf-8'),
            readFile(path.join(projectPath, 'pyproject.toml'), 'utf-8').catch(() => null),
        ]);

        const packages = this.parseLockfile(lockfileRaw, lockfilePath);
        const projectName = pyprojectRaw ? this.extractProjectName(pyprojectRaw) : null;
        const directNames = pyprojectRaw ? this.parsePyprojectDeps(pyprojectRaw) : new Set<string>();

        const dependencies: Dependency[] = [];
        for (const pkg of packages) {
            // Skip the root project itself
            if (pkg.isEditable) continue;
            if (projectName && this.normalizePipName(pkg.name) === this.normalizePipName(projectName)) {
                continue;
            }

            dependencies.push({
                name: this.normalizePipName(pkg.name),
                version: pkg.version,
                direct: directNames.size > 0 ? directNames.has(this.normalizePipName(pkg.name)) : true,
                ecosystem: 'uv',
                purl: this.buildPurl(pkg.name, pkg.version),
            });
        }

        return {
            projectPath,
            ecosystem: 'uv',
            dependencies,
            lockfilePath,
            scannedAt: new Date().toISOString(),
        };
    }

    /**
     * Parses uv.lock by splitting on [[package]] blocks.
     * Lightweight parser that handles the regular structure
     * without needing a full TOML library.
     */
    private parseLockfile(content: string, lockfilePath: string): UvPackage[] {
        const packages: UvPackage[] = [];
        const blocks = content.split(/^\[\[package\]\]$/m);

        for (const block of blocks) {
            if (!block.trim()) continue;

            const name = this.extractField(block, 'name');
            const version = this.extractField(block, 'version');

            if (name && version) {
                // Detect editable/virtual packages (root project)
                const isEditable = /source\s*=\s*\{[^}]*editable\s*=/.test(block) ||
                    /source\s*=\s*\{[^}]*virtual\s*=/.test(block);
                packages.push({ name, version, isEditable });
            }
        }

        if (packages.length === 0 && content.includes('[[package]]')) {
            throw new LockfileParseError(lockfilePath, 'Failed to parse any packages from uv.lock');
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
     * Extracts the project name from `pyproject.toml`.
     * Looks for `name = "..."` under `[project]`.
     */
    private extractProjectName(content: string): string | null {
        let inProjectSection = false;

        for (const rawLine of content.split('\n')) {
            const line = rawLine.trim();

            if (line.startsWith('[')) {
                inProjectSection = line === '[project]';
                continue;
            }

            if (inProjectSection) {
                const match = line.match(/^name\s*=\s*"([^"]*)"/);
                if (match) return match[1];
            }
        }

        return null;
    }

    /**
     * Parses `pyproject.toml` to extract direct dependency names.
     *
     * Looks for:
     *   - `[project]` → `dependencies = [...]` (PEP 621)
     *   - `[project.optional-dependencies]` (extras)
     *   - `[dependency-groups]` (PEP 735, used by uv for dev deps)
     *
     * Dependency strings follow PEP 508:
     *   - `"requests>=2.31.0"`
     *   - `"flask[dotenv]>=3.0"`
     *   - `"black"` (bare name)
     */
    private parsePyprojectDeps(content: string): Set<string> {
        const directNames = new Set<string>();

        // Extract dependencies from PEP 621 [project] dependencies array
        this.extractInlineArray(content, directNames);

        // Extract from [dependency-groups] sections (PEP 735)
        this.extractDependencyGroups(content, directNames);

        return directNames;
    }

    /**
     * Extracts dependency names from PEP 621 `dependencies = [...]` arrays
     * and `[project.optional-dependencies]` sections.
     */
    private extractInlineArray(content: string, directNames: Set<string>): void {
        // Match multi-line array patterns like:
        // dependencies = [
        //     "requests>=2.31.0",
        //     "flask",
        // ]
        const arrayRegex = /(?:^dependencies|^[a-zA-Z0-9_-]+)\s*=\s*\[([^\]]*)\]/gm;
        let match;
        while ((match = arrayRegex.exec(content)) !== null) {
            const arrayContent = match[1];
            this.extractPepNames(arrayContent, directNames);
        }
    }

    /**
     * Extracts dependency names from [dependency-groups] sections.
     * Format:
     * ```toml
     * [dependency-groups]
     * dev = ["pytest>=7.0", "black"]
     * ```
     */
    private extractDependencyGroups(content: string, directNames: Set<string>): void {
        let inDepGroups = false;

        for (const rawLine of content.split('\n')) {
            const line = rawLine.trim();

            if (line.startsWith('[')) {
                inDepGroups = line === '[dependency-groups]';
                continue;
            }

            if (inDepGroups && line && !line.startsWith('#')) {
                // Match: dev = ["pytest>=7.0", "black"]
                const arrayMatch = line.match(/^[a-zA-Z0-9_-]+\s*=\s*\[([^\]]*)\]/);
                if (arrayMatch) {
                    this.extractPepNames(arrayMatch[1], directNames);
                }
            }
        }
    }

    /**
     * Extracts PEP 508 package names from a comma-separated
     * list of quoted dependency strings.
     */
    private extractPepNames(content: string, directNames: Set<string>): void {
        const depStrings = content.match(/"([^"]*)"/g);
        if (!depStrings) return;

        for (const quoted of depStrings) {
            const depStr = quoted.replace(/"/g, '').trim();
            if (!depStr) continue;

            // PEP 508: name is everything before the first specifier char
            const nameMatch = depStr.match(/^([a-zA-Z0-9_][a-zA-Z0-9._-]*)/);
            if (nameMatch && nameMatch[1]) {
                directNames.add(this.normalizePipName(nameMatch[1]));
            }
        }
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
     * Per purl spec, the type is "pypi" (not "uv").
     */
    private buildPurl(name: string, version: string): string {
        return `pkg:pypi/${this.normalizePipName(name)}@${version}`;
    }
}

// ─── Internal types ──────────────────────────────────────────────

interface UvPackage {
    name: string;
    version: string;
    isEditable: boolean;
}
