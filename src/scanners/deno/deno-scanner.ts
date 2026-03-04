import { readFile } from 'fs/promises';
import { existsSync } from 'fs';
import path from 'path';
import type { DependencyScanner } from '../scanner.interface.js';
import type { Dependency, Ecosystem, ScanResult } from '../../core/types.js';
import { LockfileParseError } from '../../core/errors.js';

/**
 * Deno dependency scanner.
 *
 * Limitations:
 * - HTTPS/remote imports (deno.lock `remote` section) are not scanned.
 * - JSR packages are not directly supported by OSV so vulnerability scan will fail
 *
 * deno.lock v4/v5 format:
 * ```json
 * {
 *   "version": "4",
 *   "specifiers": {
 *     "jsr:@std/assert@^1.0.0": "1.0.10",
 *     "npm:express@^4.18.0": "4.21.2"
 *   },
 *   "jsr": {
 *     "@std/assert@1.0.10": { "integrity": "..." },
 *     "@std/internal@1.0.6": { "integrity": "..." }
 *   },
 *   "npm": {
 *     "express@4.21.2": { "integrity": "...", "dependencies": {...} }
 *   }
 * }
 * ```
 *
 * deno.lock v3 format:
 * ```json
 * {
 *   "version": "3",
 *   "packages": {
 *     "specifiers": {
 *       "jsr:@std/path@^1.0.0": "jsr:@std/path@1.0.8",
 *       "npm:hono@^4.0.0": "npm:hono@4.6.20"
 *     },
 *     "jsr": {
 *       "@std/path@1.0.8": { "integrity": "..." },
 *       "@std/internal@1.0.6": { "integrity": "..." }
 *     },
 *     "npm": {
 *       "hono@4.6.20": { "integrity": "...", "dependencies": {...} }
 *     }
 *   }
 * }
 * ```
 */
export class DenoScanner implements DependencyScanner {
  readonly ecosystem: Ecosystem = 'deno';
  readonly lockfileNames = ['deno.lock'];

  async detect(projectPath: string): Promise<string | null> {
    for (const name of this.lockfileNames) {
      const lockfilePath = path.join(projectPath, name);
      if (existsSync(lockfilePath)) return lockfilePath;
    }
    return null;
  }

  async scan(projectPath: string, lockfilePath: string): Promise<ScanResult> {
    const lockfileRaw = await readFile(lockfilePath, 'utf-8');

    let lockfile: DenoLockfile;
    try {
      lockfile = JSON.parse(lockfileRaw);
    } catch {
      throw new LockfileParseError(lockfilePath, 'Invalid JSON');
    }

    const dependencies = this.parseLockfile(lockfile);

    return {
      projectPath,
      ecosystem: 'deno',
      dependencies,
      lockfilePath,
      scannedAt: new Date().toISOString(),
    };
  }



  /**
   * Parses the lockfile and extracts dependencies from both
   * npm and jsr package registries.
   *
   * Supports v3 (packages nested under `packages`), v4, and v5 (top-level jsr/npm sections).
   * Uses lockfile specifiers to determine direct vs transitive dependencies.
   */
  private parseLockfile(lockfile: DenoLockfile): Dependency[] {
    const deps: Dependency[] = [];

    // Extract direct dependencies from lockfile specifiers
    const directNames = this.extractDirectDependencies(lockfile);

    // Normalize v3 vs v4/v5 structure (prefer top-level, fall back to nested)
    const jsrPackages = lockfile.jsr ?? lockfile.packages?.jsr ?? {};
    const npmPackages = lockfile.npm ?? lockfile.packages?.npm ?? {};

    // Parse JSR packages: keys are like "@std/assert@1.0.10"
    for (const key of Object.keys(jsrPackages)) {
      const parsed = this.parsePackageKey(key);
      if (!parsed) continue;

      deps.push({
        name: parsed.name,
        version: parsed.version,
        direct: directNames.has(`jsr:${parsed.name}`),
        ecosystem: 'deno', // JSR packages belong to Deno ecosystem
        purl: this.buildJsrPurl(parsed.name, parsed.version),
      });
    }

    // Parse npm packages: keys are like "express@4.21.2"
    for (const key of Object.keys(npmPackages)) {
      const parsed = this.parsePackageKey(key);
      if (!parsed) continue;

      deps.push({
        name: parsed.name,
        version: parsed.version,
        direct: directNames.has(`npm:${parsed.name}`),
        ecosystem: 'npm', // npm packages belong to npm ecosystem (for CVE tracking)
        purl: this.buildNpmPurl(parsed.name, parsed.version),
      });
    }

    return deps;
  }

  /**
   * Extracts direct dependency names from lockfile specifiers.
   *
   * Returns a set of ecosystem-qualified package names like "jsr:@std/assert" or "npm:express".
   * The ecosystem prefix prevents collisions if the same package name exists in both registries.
   */
  private extractDirectDependencies(lockfile: DenoLockfile): Set<string> {
    const directNames = new Set<string>();

    // Get specifiers from v3 (packages.specifiers) or v4/v5 (top-level specifiers)
    const specifiers = lockfile.specifiers ?? lockfile.packages?.specifiers ?? {};

    for (const [constraint, resolved] of Object.entries(specifiers)) {
      // Skip non-package URL schemes (file:, https:, data:, etc.)
      if (resolved.startsWith('file:') || resolved.startsWith('https:') || resolved.startsWith('http:') || resolved.startsWith('data:')) {
        continue;
      }

      // Determine ecosystem from constraint
      let ecosystem: 'jsr' | 'npm' | null = null;
      if (constraint.startsWith('jsr:')) {
        ecosystem = 'jsr';
      } else if (constraint.startsWith('npm:')) {
        ecosystem = 'npm';
      }

      if (!ecosystem) continue; // Skip if we can't determine ecosystem

      let resolvedKey = resolved;

      if (resolved.startsWith('jsr:') || resolved.startsWith('npm:')) {
        // v3 or some v4 formats: resolved is like "jsr:@std/path@1.0.8" or "npm:express@4.21.2"
        resolvedKey = resolved.replace(/^(jsr:|npm:)/, '');
        const parsed = this.parsePackageKey(resolvedKey);
        if (parsed) {
          directNames.add(`${ecosystem}:${parsed.name}`);
        }
      } else {
        // v4/v5 format: resolved is just the version like "1.0.10"
        // Extract name from constraint key and use directly
        const name = this.extractNameFromSpecifier(constraint);
        if (name) {
          directNames.add(`${ecosystem}:${name}`);
        }
      }
    }

    return directNames;
  }

  /**
   * Parses a package key like "@std/assert@1.0.10" or "express@4.21.2"
   * into { name, version }.
   *
   * Handles scoped packages where the name starts with @ (e.g., @std/assert).
   * In that case the version separator is the LAST @ sign.
   */
  private parsePackageKey(key: string): { name: string; version: string } | null {
    // Find the last @ which separates name from version
    const lastAtIndex = key.lastIndexOf('@');
    if (lastAtIndex <= 0) return null;

    const name = key.slice(0, lastAtIndex);
    const version = key.slice(lastAtIndex + 1);

    if (!name || !version) return null;
    return { name, version };
  }



  /**
   * Extracts the package name from a Deno import specifier.
   *
   * Examples:
   *   "jsr:@std/assert@^1.0.0" → "@std/assert"
   *   "npm:express@^4.18.0"    → "express"
   *   "npm:@hono/hono@^4.0.0"  → "@hono/hono"
   *   "lodash" (bare)          → "lodash"
   */
  private extractNameFromSpecifier(specifier: string): string | null {
    // Strip jsr: or npm: prefix
    const withoutPrefix = specifier.replace(/^(jsr:|npm:)/, '');
    if (!withoutPrefix) return null;

    // For scoped packages (@scope/name@version), find the version @
    if (withoutPrefix.startsWith('@')) {
      // Find the @ after the scoped name portion
      const slashIndex = withoutPrefix.indexOf('/');
      if (slashIndex === -1) return null;
      const afterSlash = withoutPrefix.indexOf('@', slashIndex);
      if (afterSlash === -1) return withoutPrefix; // No version constraint
      return withoutPrefix.slice(0, afterSlash);
    }

    // Unscoped: "express@^4.18.0" → "express" or bare "lodash" → "lodash"
    const atIndex = withoutPrefix.indexOf('@');
    if (atIndex === -1) return withoutPrefix;
    return withoutPrefix.slice(0, atIndex);
  }

  /**
   * Builds a purl for a JSR package.
   *
   * JSR packages use the "jsr" purl type (non-standard but descriptive).
   * For scoped packages, both @ and all / characters are percent-encoded.
   * Example: `pkg:jsr/%40std%2Fassert@1.0.10`
   */
  private buildJsrPurl(name: string, version: string): string {
    if (name.startsWith('@')) {
      // Encode @ and all / characters: @scope/sub/name -> %40scope%2Fsub%2Fname
      const encoded = '%40' + name.slice(1).replace(/\//g, '%2F');
      return `pkg:jsr/${encoded}@${version}`;
    }
    return `pkg:jsr/${name}@${version}`;
  }

  /**
   * Builds a purl for an npm package used via Deno.
   *
   * Uses the standard npm purl type since these are npm packages.
   * Per npm purl spec, only @ is encoded, / remains as namespace separator.
   * Example: `pkg:npm/%40std/assert@1.0.10` or `pkg:npm/express@4.21.2`
   */
  private buildNpmPurl(name: string, version: string): string {
    if (name.startsWith('@')) {
      return `pkg:npm/%40${name.slice(1)}@${version}`;
    }
    return `pkg:npm/${name}@${version}`;
  }
}

// ─── Types for deno.lock parsing ─────────────────────────────────

/** Represents the deno.lock file structure (supports v3, v4, and v5) */
interface DenoLockfile {
  version?: string;
  /** v4/v5: top-level specifiers mapping (constraint -> resolved version) */
  specifiers?: Record<string, string>;
  /** v4/v5: top-level jsr packages */
  jsr?: Record<string, DenoLockfilePackage>;
  /** v4/v5: top-level npm packages */
  npm?: Record<string, DenoLockfilePackage>;
  /** v3: all packages nested under this key */
  packages?: {
    specifiers?: Record<string, string>;
    jsr?: Record<string, DenoLockfilePackage>;
    npm?: Record<string, DenoLockfilePackage>;
  };
}

interface DenoLockfilePackage {
  integrity?: string;
  /** Dependencies: npm uses Record<string, string> (name -> version), JSR uses string[] (specifier list) */
  dependencies?: Record<string, string> | string[];
}