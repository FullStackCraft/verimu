import { readFile } from 'fs/promises';
import { existsSync } from 'fs';
import path from 'path';
import { parse as parseYaml } from 'yaml';
import type { DependencyScanner } from '../scanner.interface.js';
import type { Dependency, Ecosystem, ScanResult } from '../../core/types.js';
import { LockfileParseError } from '../../core/errors.js';

/**
 * Yarn dependency scanner.
 *
 * Supports Yarn v1 (Classic) and Yarn v2/v3/v4 (Berry) lockfile formats.
 * 
 * - Yarn v1: Plain text format with indentation
 * - Yarn v2+: YAML-based format with __metadata section
 *
 * Parses yarn.lock to extract the full resolved dependency tree.
 * Also reads package.json to determine which dependencies are direct vs transitive.
 *
 * Note: Yarn uses the npm ecosystem since it's an alternative
 * package manager for the npm registry.
 */
export class YarnScanner implements DependencyScanner {
    readonly ecosystem: Ecosystem = 'npm';
    readonly lockfileNames = ['yarn.lock'];

    async detect(projectPath: string): Promise<string | null> {
        const lockfilePath = path.join(projectPath, 'yarn.lock');
        return existsSync(lockfilePath) ? lockfilePath : null;
    }

    async scan(projectPath: string, lockfilePath: string): Promise<ScanResult> {
        const [lockfileRaw, packageJsonRaw] = await Promise.all([
            readFile(lockfilePath, 'utf-8'),
            readFile(path.join(projectPath, 'package.json'), 'utf-8').catch(() => null),
        ]);

        // Determine direct dependency names from package.json
        const directNames = new Set<string>();
        if (packageJsonRaw) {
            try {
                const pkg = JSON.parse(packageJsonRaw);
                for (const name of Object.keys(pkg.dependencies ?? {})) {
                    directNames.add(name);
                }
                for (const name of Object.keys(pkg.devDependencies ?? {})) {
                    directNames.add(name);
                }
            } catch {
                // If package.json can't be parsed, all deps are "unknown" direct status
            }
        }

        const dependencies = this.parseLockfile(lockfileRaw, lockfilePath, directNames);

        return {
            projectPath,
            ecosystem: 'npm',
            dependencies,
            lockfilePath,
            scannedAt: new Date().toISOString(),
        };
    }

    /**
     * Parses yarn.lock file and extracts dependencies.
     * Automatically detects and handles both v1 (Classic) and v2+ (Berry) formats.
     */
    private parseLockfile(
        content: string,
        lockfilePath: string,
        directNames: Set<string>
    ): Dependency[] {
        try {
            // Detect Yarn version by checking for v2+ indicators
            const isV2Plus = this.isYarnV2Plus(content);

            if (isV2Plus) {
                return this.parseLockfileV2Plus(content, lockfilePath, directNames);
            } else {
                return this.parseLockfileV1(content, lockfilePath, directNames);
            }
        } catch (err) {
            throw new LockfileParseError(
                lockfilePath,
                `Failed to parse yarn.lock: ${err instanceof Error ? err.message : 'Unknown error'}`
            );
        }
    }

    /**
     * Detects if the lockfile is Yarn v2+ (Berry) format.
     * v2+ uses YAML format and contains __metadata section.
     */
    private isYarnV2Plus(content: string): boolean {
        return content.startsWith('__metadata:') ||
            content.includes('\n__metadata:');
    }

    /**
     * Parses Yarn v2+ (Berry) lockfile format.
     * 
     * Yarn v2+ format (YAML):
     * ```yaml
     * __metadata:
     *   version: 6
     * 
     * "package-name@npm:^1.0.0":
     *   version: 1.2.3
     *   resolution: "package-name@npm:1.2.3"
     *   dependencies:
     *     dep1: ^2.0.0
     *   checksum: ...
     *   languageName: node
     *   linkType: hard
     * ```
     */
    private parseLockfileV2Plus(
        content: string,
        lockfilePath: string,
        directNames: Set<string>
    ): Dependency[] {
        const deps: Dependency[] = [];
        const seen = new Map<string, boolean>();

        try {
            const parsed = parseYaml(content);

            if (!parsed || typeof parsed !== 'object') {
                throw new Error('Invalid YAML format');
            }

            for (const [key, value] of Object.entries(parsed)) {
                // Skip metadata and workspace entries
                if (key === '__metadata' || key.includes('@workspace:')) {
                    continue;
                }

                if (typeof value !== 'object' || value === null) {
                    continue;
                }

                const entry = value as Record<string, any>;

                // Extract package name - prefer resolution field as it contains the real package
                let name: string | null = null;
                if (entry.resolution && typeof entry.resolution === 'string') {
                    name = this.extractPackageNameFromResolution(entry.resolution);
                }
                // Fall back to extracting from key if resolution is not available
                if (!name) {
                    name = this.extractPackageNameV2Plus(key);
                }

                const version = entry.version;

                if (!name || !version || typeof version !== 'string') {
                    continue;
                }

                // Deduplicate by name@version
                const depKey = `${name}@${version}`;
                if (seen.has(depKey)) {
                    continue;
                }
                seen.set(depKey, true);

                deps.push({
                    name,
                    version,
                    direct: directNames.has(name),
                    ecosystem: 'npm',
                    purl: this.buildPurl(name, version),
                });
            }
        } catch (err) {
            throw new Error(`Failed to parse Yarn v2+ lockfile: ${err instanceof Error ? err.message : 'Unknown error'}`);
        }

        return deps;
    }

    /**
     * Extracts package name from Yarn v2+ resolution field.
     * The resolution field contains the real package name.
     * Examples:
     *   "express@npm:4.18.2" → "express"
     *   "@types/node@npm:20.11.5" → "@types/node"
     *   "lodash@npm:4.17.21" → "lodash"
     */
    private extractPackageNameFromResolution(resolution: string): string | null {
        // Resolution format: "package-name@npm:version"

        // Handle scoped packages: "@scope/name@npm:version"
        if (resolution.startsWith('@')) {
            const match = resolution.match(/^(@[^@]+\/[^@]+)@/);
            if (match) {
                return match[1];
            }
        }

        // Handle regular packages: "package@npm:version"
        const match = resolution.match(/^([^@]+)@/);
        if (match) {
            return match[1];
        }

        return null;
    }

    /**
     * Extracts package name from Yarn v2+ package key.
     * Examples:
     *   "express@npm:^4.18.0" → "express"
     *   "@types/node@npm:^20.0.0" → "@types/node"
     *   "pkg@npm:other@npm:^1.0.0" → "pkg" (aliased packages)
     */
    private extractPackageNameV2Plus(key: string): string | null {
        // Remove the @npm: protocol prefix and version specifier
        // Format: "package-name@npm:^version" or "@scope/name@npm:^version"

        // Handle scoped packages: "@scope/name@npm:^version"
        if (key.startsWith('@')) {
            const match = key.match(/^(@[^@]+\/[^@]+)@/);
            if (match) {
                return match[1];
            }
        }

        // Handle regular packages: "package@npm:^version"
        const match = key.match(/^([^@]+)@/);
        if (match) {
            return match[1];
        }

        return null;
    }

    /**
     * Parses Yarn v1 (Classic) lockfile format.
     *
     * Yarn v1 format:
     * ```
     * "package-name@^1.0.0":
     *   version "1.2.3"
     *   resolved "https://..."
     *   integrity sha512-...
     *   dependencies:
     *     dep1 "^2.0.0"
     * ```
     */
    private parseLockfileV1(
        content: string,
        lockfilePath: string,
        directNames: Set<string>
    ): Dependency[] {
        const deps: Dependency[] = [];
        const seen = new Map<string, boolean>(); // Track unique name@version pairs

        const lines = content.split('\n');
        let currentPackage: { names: string[]; version?: string } | null = null;

        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];

            // Skip comments and empty lines
            if (line.trim().startsWith('#') || line.trim() === '') {
                continue;
            }

            // Package declaration: "name@version", name@version (with or without quotes)
            // Can be multiple aliases separated by comma: "pkg@^1.0.0", pkg@1.2.3:
            if (line.match(/^["\w@]/) && line.includes(':') && !line.startsWith('  ')) {
                // Save previous package
                if (currentPackage?.version) {
                    this.addDependency(currentPackage, directNames, seen, deps);
                }

                // Parse package name(s)
                const pkgLine = line.substring(0, line.lastIndexOf(':'));
                const names = pkgLine
                    .split(',')
                    .map((s) => s.trim().replace(/^["']|["']$/g, ''))
                    .map((s) => this.extractPackageName(s))
                    .filter((s): s is string => !!s);

                currentPackage = { names, version: undefined };
            }
            // Version field
            else if (line.trim().startsWith('version ') && currentPackage) {
                const match = line.match(/version\s+"([^"]+)"/);
                if (match) {
                    currentPackage.version = match[1];
                }
            }
        }

        // Don't forget the last package
        if (currentPackage?.version) {
            this.addDependency(currentPackage, directNames, seen, deps);
        }

        return deps;
    }

    /**
     * Adds a dependency to the result list (deduplicates by name@version)
     */
    private addDependency(
        pkg: { names: string[]; version?: string },
        directNames: Set<string>,
        seen: Map<string, boolean>,
        deps: Dependency[]
    ): void {
        if (!pkg.version) return;

        // Use the first name as the canonical package name
        const name = pkg.names[0];
        if (!name) return;

        // Deduplicate: only add once per name@version
        const key = `${name}@${pkg.version}`;
        if (seen.has(key)) return;
        seen.set(key, true);

        deps.push({
            name,
            version: pkg.version,
            direct: directNames.has(name),
            ecosystem: 'npm',
            purl: this.buildPurl(name, pkg.version),
        });
    }

    /**
     * Extracts package name from yarn.lock package declaration.
     * Examples:
     *   "express@^4.18.0" → "express"
     *   "@types/node@^20.0.0" → "@types/node"
     *   "pkg@npm:other@^1.0.0" → "pkg" (aliased packages)
     */
    private extractPackageName(pkgDeclaration: string): string | null {
        // Handle npm: aliases (e.g., "pkg@npm:other@^1.0.0")
        if (pkgDeclaration.includes('@npm:')) {
            const beforeAlias = pkgDeclaration.split('@npm:')[0];
            return beforeAlias || null;
        }

        // Standard format: name@version
        // For scoped packages: @scope/name@version
        if (pkgDeclaration.startsWith('@')) {
            // Scoped package: @scope/name@version
            const parts = pkgDeclaration.split('@');
            // parts = ['', 'scope/name', 'version']
            if (parts.length >= 3) {
                return `@${parts[1]}`;
            }
        } else {
            // Regular package: name@version
            const atIndex = pkgDeclaration.indexOf('@');
            if (atIndex > 0) {
                return pkgDeclaration.substring(0, atIndex);
            }
        }

        return null;
    }

    /**
     * Builds a purl (Package URL) for an npm package.
     *
     * Per the purl spec:
     * "The npm scope @ sign prefix is always percent encoded."
     *
     * So @types/node@20.11.5 → pkg:npm/%40types/node@20.11.5
     * And express@4.18.2 → pkg:npm/express@4.18.2
     */
    private buildPurl(name: string, version: string): string {
        if (name.startsWith('@')) {
            // Scoped: encode the @ as %40 per purl spec
            return `pkg:npm/%40${name.slice(1)}@${version}`;
        }
        return `pkg:npm/${name}@${version}`;
    }
}
