import { readFile } from 'fs/promises';
import { existsSync } from 'fs';
import path from 'path';
import type { DependencyScanner } from '../scanner.interface.js';
import type { Dependency, Ecosystem, ScanResult } from '../../core/types.js';
import { LockfileParseError } from '../../core/errors.js';

/**
 * Python / pip dependency scanner.
 *
 * Supports multiple Python dependency file formats (in priority order):
 *   1. `requirements.txt` — flat list of pinned dependencies
 *   2. `Pipfile.lock` — Pipenv lock file with exact versions
 *
 * For `requirements.txt`, all listed packages are treated as direct
 * dependencies (the file doesn't distinguish direct vs transitive).
 * For `Pipfile.lock`, `default` packages are direct and `develop`
 * packages are dev dependencies.
 *
 * Limitation: `requirements.txt` doesn't capture transitive deps unless
 * generated with `pip freeze`. If using `pip freeze` output, all deps
 * are listed but we can't distinguish direct vs transitive.
 */
export class PipScanner implements DependencyScanner {
  readonly ecosystem: Ecosystem = 'pip';
  readonly lockfileNames = ['Pipfile.lock', 'requirements.txt'];

  async detect(projectPath: string): Promise<string | null> {
    // Check in priority order
    for (const lockfile of this.lockfileNames) {
      const fullPath = path.join(projectPath, lockfile);
      if (existsSync(fullPath)) return fullPath;
    }
    return null;
  }

  async scan(projectPath: string, lockfilePath: string): Promise<ScanResult> {
    const raw = await readFile(lockfilePath, 'utf-8');
    const filename = path.basename(lockfilePath);

    let dependencies: Dependency[];

    if (filename === 'Pipfile.lock') {
      dependencies = this.parsePipfileLock(raw, lockfilePath);
    } else {
      dependencies = await this.parseRequirementsTxt(raw, lockfilePath);
    }

    return {
      projectPath,
      ecosystem: 'pip',
      dependencies,
      lockfilePath,
      scannedAt: new Date().toISOString(),
    };
  }

  /**
   * Parses `requirements.txt` format.
   *
   * Supports:
   *   - `package==1.2.3` (pinned) — REQUIRED
   *   - Comments (`#`) and blank lines are skipped
   *   - `-r other-file.txt` (include directive) — recursively parsed
   *   - `--index-url` and other pip flags — skipped
   *
   * Throws if any dependency is not strictly pinned with ==.
   * Use `pip freeze` to generate a properly pinned requirements.txt.
   */
  private async parseRequirementsTxt(
    content: string,
    lockfilePath: string,
    visited: Set<string> = new Set()
  ): Promise<Dependency[]> {
    const deps: Dependency[] = [];
    const currentDir = path.dirname(lockfilePath);
    const normalizedPath = path.resolve(lockfilePath);

    // Prevent circular includes
    if (visited.has(normalizedPath)) {
      return deps;
    }
    visited.add(normalizedPath);

    for (const rawLine of content.split('\n')) {
      const line = rawLine.trim();

      // Skip comments and blank lines
      if (!line || line.startsWith('#')) {
        continue;
      }

      // Handle -r / --requirement includes
      const includeMatch = line.match(/^-r\s+(.+)$/) || line.match(/^--requirement\s+(.+)$/);
      if (includeMatch) {
        const includePath = path.resolve(currentDir, includeMatch[1].trim());
        if (existsSync(includePath)) {
          const includeContent = await readFile(includePath, 'utf-8');
          const includedDeps = await this.parseRequirementsTxt(includeContent, includePath, visited);
          deps.push(...includedDeps);
        }
        continue;
      }

      // Skip other pip flags (--index-url, -e, etc.)
      if (line.startsWith('-') || line.startsWith('--')) {
        continue;
      }

      // Parse strictly pinned "package==version" only
      const pinnedMatch = line.match(/^([a-zA-Z0-9_][a-zA-Z0-9._-]*)\s*==\s*([^,\s]+)$/);
      if (pinnedMatch) {
        const [, name, version] = pinnedMatch;
        if (name && version) {
          deps.push({
            name: this.normalizePipName(name),
            version,
            direct: true, // requirements.txt doesn't distinguish
            ecosystem: 'pip',
            purl: this.buildPurl(name, version),
          });
        }
        continue;
      }

      // Check if it's a dependency line with non-pinned version specifier
      const depMatch = line.match(/^([a-zA-Z0-9_][a-zA-Z0-9._-]*)\s*([~=!<>].*)$/);
      if (depMatch) {
        throw new LockfileParseError(
          lockfilePath,
          `Non-pinned dependency detected: "${line}". Use pip freeze or Pipfile.lock.`
        );
      }
    }

    return deps;
  }

  /**
   * Parses `Pipfile.lock` (JSON format from Pipenv).
   *
   * Structure:
   * ```json
   * {
   *   "_meta": { ... },
   *   "default": {
   *     "requests": { "version": "==2.31.0", ... }
   *   },
   *   "develop": {
   *     "pytest": { "version": "==7.4.0", ... }
   *   }
   * }
   * ```
   */
  private parsePipfileLock(content: string, lockfilePath: string): Dependency[] {
    let lockfile: PipfileLock;
    try {
      lockfile = JSON.parse(content);
    } catch {
      throw new LockfileParseError(lockfilePath, 'Invalid JSON in Pipfile.lock');
    }

    const deps: Dependency[] = [];

    // Parse "default" (production) dependencies
    if (lockfile.default) {
      for (const [name, info] of Object.entries(lockfile.default)) {
        const version = info.version?.replace(/^==/, '') ?? '';
        if (version) {
          deps.push({
            name: this.normalizePipName(name),
            version,
            direct: true,
            ecosystem: 'pip',
            purl: this.buildPurl(name, version),
          });
        }
      }
    }

    // Parse "develop" dependencies
    if (lockfile.develop) {
      for (const [name, info] of Object.entries(lockfile.develop)) {
        const version = info.version?.replace(/^==/, '') ?? '';
        if (version) {
          deps.push({
            name: this.normalizePipName(name),
            version,
            direct: true,
            ecosystem: 'pip',
            purl: this.buildPurl(name, version),
          });
        }
      }
    }

    return deps;
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
   * Per purl spec, the type is "pypi" (not "pip").
   */
  private buildPurl(name: string, version: string): string {
    return `pkg:pypi/${this.normalizePipName(name)}@${version}`;
  }
}

// ─── Types for Pipfile.lock parsing ──────────────────────────────

interface PipfileLock {
  _meta?: Record<string, unknown>;
  default?: Record<string, PipfileLockEntry>;
  develop?: Record<string, PipfileLockEntry>;
}

interface PipfileLockEntry {
  version?: string;
  hashes?: string[];
  markers?: string;
  index?: string;
}
