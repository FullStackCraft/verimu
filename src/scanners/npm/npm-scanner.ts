import { readFile } from 'fs/promises';
import { existsSync } from 'fs';
import path from 'path';
import type { DependencyScanner } from '../scanner.interface.js';
import type { Dependency, Ecosystem, ScanResult } from '../../core/types.js';
import { LockfileParseError } from '../../core/errors.js';

/**
 * npm / Node.js dependency scanner.
 *
 * Parses package-lock.json (v2/v3 format) to extract the full
 * resolved dependency tree. Also reads package.json to determine
 * which dependencies are direct vs transitive.
 */
export class NpmScanner implements DependencyScanner {
  readonly ecosystem: Ecosystem = 'npm';
  readonly lockfileNames = ['package-lock.json'];

  async detect(projectPath: string): Promise<string | null> {
    const lockfilePath = path.join(projectPath, 'package-lock.json');
    return existsSync(lockfilePath) ? lockfilePath : null;
  }

  async scan(projectPath: string, lockfilePath: string): Promise<ScanResult> {
    const [lockfileRaw, packageJsonRaw] = await Promise.all([
      readFile(lockfilePath, 'utf-8'),
      readFile(path.join(projectPath, 'package.json'), 'utf-8').catch(() => null),
    ]);

    let lockfile: NpmLockfile;
    try {
      lockfile = JSON.parse(lockfileRaw);
    } catch {
      throw new LockfileParseError(lockfilePath, 'Invalid JSON');
    }

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

    const dependencies = this.parseLockfile(lockfile, directNames);

    return {
      projectPath,
      ecosystem: 'npm',
      dependencies,
      lockfilePath,
      scannedAt: new Date().toISOString(),
    };
  }

  /**
   * Parses package-lock.json and extracts dependencies.
   * Supports lockfile v2 and v3 (uses the `packages` field).
   * Falls back to `dependencies` field for lockfile v1.
   */
  private parseLockfile(lockfile: NpmLockfile, directNames: Set<string>): Dependency[] {
    const deps: Dependency[] = [];

    if (lockfile.packages) {
      // Lockfile v2/v3: `packages` is a flat map of "node_modules/name" → info
      for (const [pkgPath, pkgInfo] of Object.entries(lockfile.packages)) {
        // Skip the root package (empty string key)
        if (pkgPath === '') continue;

        // Extract package name from the path
        // e.g., "node_modules/express" → "express"
        // e.g., "node_modules/@types/node" → "@types/node"
        const name = this.extractPackageName(pkgPath);
        if (!name || !pkgInfo.version) continue;

        // Skip link: true entries (workspace references)
        if (pkgInfo.link) continue;

        deps.push({
          name,
          version: pkgInfo.version,
          direct: directNames.has(name),
          ecosystem: 'npm',
          purl: this.buildPurl(name, pkgInfo.version),
        });
      }
    } else if (lockfile.dependencies) {
      // Lockfile v1 fallback: `dependencies` is a nested tree
      this.parseDependenciesV1(lockfile.dependencies, directNames, deps);
    }

    return deps;
  }

  /**
   * Builds a purl (Package URL) for an npm package.
   *
   * Per the purl spec (https://github.com/package-url/purl-spec/blob/main/types-doc/npm-definition.md):
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

  /** Extracts the package name from a node_modules path */
  private extractPackageName(pkgPath: string): string | null {
    // "node_modules/@scope/name" → "@scope/name"
    // "node_modules/name" → "name"
    // "node_modules/a/node_modules/b" → "b" (nested)
    const parts = pkgPath.split('node_modules/');
    const last = parts[parts.length - 1];
    return last || null;
  }

  /** Recursively parses lockfile v1 `dependencies` tree */
  private parseDependenciesV1(
    depsObj: Record<string, NpmLockfileV1Dep>,
    directNames: Set<string>,
    result: Dependency[]
  ): void {
    for (const [name, info] of Object.entries(depsObj)) {
      if (info.version) {
        result.push({
          name,
          version: info.version,
          direct: directNames.has(name),
          ecosystem: 'npm',
          purl: this.buildPurl(name, info.version),
        });
      }
      // Recurse into nested dependencies
      if (info.dependencies) {
        this.parseDependenciesV1(info.dependencies, directNames, result);
      }
    }
  }
}

// ─── Types for package-lock.json parsing ─────────────────────────

interface NpmLockfile {
  name?: string;
  version?: string;
  lockfileVersion?: number;
  packages?: Record<string, NpmLockfilePackage>;
  dependencies?: Record<string, NpmLockfileV1Dep>;
}

interface NpmLockfilePackage {
  version?: string;
  resolved?: string;
  integrity?: string;
  dev?: boolean;
  optional?: boolean;
  link?: boolean;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

interface NpmLockfileV1Dep {
  version?: string;
  resolved?: string;
  integrity?: string;
  requires?: Record<string, string>;
  dependencies?: Record<string, NpmLockfileV1Dep>;
}
