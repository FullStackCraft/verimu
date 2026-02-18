import { readFile } from 'fs/promises';
import { existsSync } from 'fs';
import path from 'path';
import { parse as parseYaml } from 'yaml';
import type { DependencyScanner } from '../scanner.interface.js';
import type { Dependency, Ecosystem, ScanResult } from '../../core/types.js';
import { LockfileParseError } from '../../core/errors.js';

/**
 * pnpm dependency scanner.
 *
 * Parses pnpm-lock.yaml to extract the full resolved dependency tree
 * and determine which dependencies are direct vs transitive.
 *
 * Note: pnpm uses the npm ecosystem since it's an alternative
 * package manager for the npm registry.
 */
export class PnpmScanner implements DependencyScanner {
    readonly ecosystem: Ecosystem = 'npm';
    readonly lockfileNames = ['pnpm-lock.yaml'];

    async detect(projectPath: string): Promise<string | null> {
        const lockfilePath = path.join(projectPath, 'pnpm-lock.yaml');
        return existsSync(lockfilePath) ? lockfilePath : null;
    }

    async scan(projectPath: string, lockfilePath: string): Promise<ScanResult> {
        const lockfileRaw = await readFile(lockfilePath, 'utf-8');

        const dependencies = this.parseLockfile(lockfileRaw, lockfilePath);

        return {
            projectPath,
            ecosystem: 'npm',
            dependencies,
            lockfilePath,
            scannedAt: new Date().toISOString(),
        };
    }

    /**
     * Parses pnpm-lock.yaml file and extracts dependencies.
     * 
     * pnpm-lock.yaml format (v5.4+):
     * ```yaml
     * lockfileVersion: 5.4
     * 
     * dependencies:
     *   express: 4.18.2
     * 
     * devDependencies:
     *   typescript: 5.0.0
     * 
     * packages:
     *   /express/4.18.2:
     *     resolution: {integrity: sha512-...}
     *     dependencies:
     *       accepts: 1.3.8
     *   /@types/node/20.11.5:
     *     resolution: {integrity: sha512-...}
     *     dev: true
     * ```
     * 
     * pnpm-lock.yaml format (v6.0+):
     * ```yaml
     * lockfileVersion: '6.0'
     * 
     * dependencies:
     *   express:
     *     specifier: ^4.18.0
     *     version: 4.18.2
     * 
     * packages:
     *   /express@4.18.2:
     *     resolution: {integrity: sha512-...}
     * ```
     */
    private parseLockfile(
        content: string,
        lockfilePath: string
    ): Dependency[] {
        try {
            const parsed = parseYaml(content);

            if (!parsed || typeof parsed !== 'object') {
                throw new Error('Invalid YAML format');
            }

            const lockfile = parsed as PnpmLockfile;

            // Determine lockfile version format
            const lockfileVersion = this.parseLockfileVersion(lockfile.lockfileVersion);

            // Extract direct dependency names from lockfile
            const directNames = this.extractDirectDependencies(lockfile);

            return this.extractDependencies(lockfile, lockfileVersion, directNames);
        } catch (err) {
            throw new LockfileParseError(
                lockfilePath,
                `Failed to parse pnpm-lock.yaml: ${err instanceof Error ? err.message : 'Unknown error'}`
            );
        }
    }

    /**
     * Extracts direct dependency names from pnpm lockfile.
     * 
     * Supports both formats:
     * - pnpm v5.x: root-level dependencies/devDependencies
     * - pnpm v6+: importers['.'].dependencies/devDependencies
     */
    private extractDirectDependencies(lockfile: PnpmLockfile): Set<string> {
        const directNames = new Set<string>();

        // Try modern format first (v6+): importers section
        if (lockfile.importers && typeof lockfile.importers === 'object') {
            const rootImporter = lockfile.importers['.'];
            if (rootImporter && typeof rootImporter === 'object') {
                // Extract from importers['.'].dependencies
                if (rootImporter.dependencies && typeof rootImporter.dependencies === 'object') {
                    for (const name of Object.keys(rootImporter.dependencies)) {
                        directNames.add(name);
                    }
                }

                // Extract from importers['.'].devDependencies
                if (rootImporter.devDependencies && typeof rootImporter.devDependencies === 'object') {
                    for (const name of Object.keys(rootImporter.devDependencies)) {
                        directNames.add(name);
                    }
                }
            }
        }

        // Fallback to legacy format (v5.x): root-level dependencies
        if (directNames.size === 0) {
            // Extract from root-level dependencies section
            if (lockfile.dependencies && typeof lockfile.dependencies === 'object') {
                for (const name of Object.keys(lockfile.dependencies)) {
                    directNames.add(name);
                }
            }

            // Extract from root-level devDependencies section
            if (lockfile.devDependencies && typeof lockfile.devDependencies === 'object') {
                for (const name of Object.keys(lockfile.devDependencies)) {
                    directNames.add(name);
                }
            }
        }

        return directNames;
    }

    /**
     * Parses lockfile version (can be string or number)
     */
    private parseLockfileVersion(version: string | number | undefined): number {
        if (typeof version === 'number') {
            return version;
        }
        if (typeof version === 'string') {
            const parsed = parseFloat(version);
            return isNaN(parsed) ? 5.4 : parsed;
        }
        return 5.4; // Default to 5.4 if not specified
    }

    /**
     * Extracts dependencies from the lockfile packages section
     */
    private extractDependencies(
        lockfile: PnpmLockfile,
        lockfileVersion: number,
        directNames: Set<string>
    ): Dependency[] {
        const deps: Dependency[] = [];
        const seen = new Map<string, boolean>();

        if (!lockfile.packages || typeof lockfile.packages !== 'object') {
            return deps;
        }

        for (const [pkgPath, pkgInfo] of Object.entries(lockfile.packages)) {
            if (!pkgInfo || typeof pkgInfo !== 'object') {
                continue;
            }

            // Skip workspace packages (e.g., "/project@workspace:*")
            if (pkgPath.includes('@workspace:')) {
                continue;
            }

            // Extract package name and version from path
            // v5.x format: "/express/4.18.2", "/@types/node/20.11.5"
            // v6+ format: "/express@4.18.2", "/@types/node@20.11.5"
            const { name, version } = this.parsePackagePath(pkgPath, lockfileVersion);

            if (!name || !version) {
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

        return deps;
    }

    /**
     * Parses package path to extract name and version.
     * 
     * pnpm v5.x format:
     *   "/express/4.18.2" → name: "express", version: "4.18.2"
     *   "/@types/node/20.11.5" → name: "@types/node", version: "20.11.5"
     *   "/accepts/1.3.8" → name: "accepts", version: "1.3.8"
     * 
     * pnpm v6+ format:
     *   "/express@4.18.2" → name: "express", version: "4.18.2"
     *   "/@types/node@20.11.5" → name: "@types/node", version: "20.11.5"
     *   "/accepts@1.3.8" → name: "accepts", version: "1.3.8"
     * 
     * Also handles peer dependency suffixes:
     *   "/pkg@1.0.0_dep@2.0.0" → name: "pkg", version: "1.0.0"
     *   "/pkg@1.0.0(dep@2.0.0)" → name: "pkg", version: "1.0.0"
     */
    private parsePackagePath(pkgPath: string, lockfileVersion: number): { name: string | null; version: string | null } {
        // Remove leading slash
        const path = pkgPath.startsWith('/') ? pkgPath.slice(1) : pkgPath;

        // Remove peer dependency suffixes (anything after _ or opening parenthesis)
        const cleanPath = path.split('_')[0].split('(')[0];

        if (!cleanPath) {
            return { name: null, version: null };
        }

        // v6+ format uses @ separator between name and version
        if (lockfileVersion >= 6) {
            return this.parseV6Format(cleanPath);
        }

        // v5.x format uses / separator between name and version
        return this.parseV5Format(cleanPath);
    }

    /**
     * Parses v6+ format: "express@4.18.2" or "@types/node@20.11.5"
     */
    private parseV6Format(path: string): { name: string | null; version: string | null } {
        // Handle scoped packages: "@scope/name@version"
        if (path.startsWith('@')) {
            // Find the last @ which separates the version
            const lastAtIndex = path.lastIndexOf('@');
            if (lastAtIndex <= 0) {
                return { name: null, version: null };
            }

            const name = path.substring(0, lastAtIndex);
            const version = path.substring(lastAtIndex + 1);

            return { name, version };
        }

        // Regular packages: "name@version"
        const atIndex = path.indexOf('@');
        if (atIndex < 0) {
            return { name: null, version: null };
        }

        const name = path.substring(0, atIndex);
        const version = path.substring(atIndex + 1);

        return { name, version };
    }

    /**
     * Parses v5.x format: "express/4.18.2" or "@types/node/20.11.5"
     */
    private parseV5Format(path: string): { name: string | null; version: string | null } {
        // Handle scoped packages: "@scope/name/version"
        if (path.startsWith('@')) {
            const parts = path.split('/');
            // parts = ['@scope', 'name', 'version']
            if (parts.length < 3) {
                return { name: null, version: null };
            }

            const name = `${parts[0]}/${parts[1]}`;
            const version = parts[2];

            return { name, version };
        }

        // Regular packages: "name/version"
        const slashIndex = path.indexOf('/');
        if (slashIndex < 0) {
            return { name: null, version: null };
        }

        const name = path.substring(0, slashIndex);
        const version = path.substring(slashIndex + 1);

        return { name, version };
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

// ─── Types for pnpm-lock.yaml parsing ─────────────────────────

interface PnpmLockfile {
    lockfileVersion?: string | number;
    // Legacy format (v5.x): root-level dependencies
    dependencies?: Record<string, string | PnpmDependencyEntry>;
    devDependencies?: Record<string, string | PnpmDependencyEntry>;
    // Modern format (v6+): importers section
    importers?: Record<string, PnpmImporter>;
    packages?: Record<string, PnpmPackageInfo>;
}

interface PnpmImporter {
    dependencies?: Record<string, PnpmDependencyEntry>;
    devDependencies?: Record<string, PnpmDependencyEntry>;
    specifiers?: Record<string, string>;
}

interface PnpmDependencyEntry {
    specifier?: string;
    version?: string;
}

interface PnpmPackageInfo {
    resolution?: {
        integrity?: string;
        tarball?: string;
    };
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
    peerDependencies?: Record<string, string>;
    dev?: boolean;
    optional?: boolean;
}
