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
  readonly lockfileNames = ['requirements.txt', 'Pipfile.lock'];

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
      dependencies = this.parseRequirementsTxt(raw, lockfilePath);
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
   *   - `package==1.2.3` (pinned)
   *   - `package>=1.2.0` (minimum — uses the specified version)
   *   - `package~=1.2.0` (compatible release)
   *   - Comments (`#`) and blank lines are skipped
   *   - `-r other-file.txt` (include directive) — skipped for now
   *   - `--index-url` and other pip flags — skipped
   */
  private parseRequirementsTxt(content: string, lockfilePath: string): Dependency[] {
    const deps: Dependency[] = [];

    for (const rawLine of content.split('\n')) {
      const line = rawLine.trim();

      // Skip comments, blank lines, flags, and include directives
      if (!line || line.startsWith('#') || line.startsWith('-') || line.startsWith('--')) {
        continue;
      }

      // Parse "package==version", "package>=version", "package~=version"
      const match = line.match(/^([a-zA-Z0-9_][a-zA-Z0-9._-]*)\s*(?:[~=!<>]=?)\s*(.+)$/);
      if (match) {
        const [, name, versionSpec] = match;
        // Extract the first version number from the spec
        const version = this.extractVersion(versionSpec);
        if (name && version) {
          deps.push({
            name: this.normalizePipName(name),
            version,
            direct: true, // requirements.txt doesn't distinguish
            ecosystem: 'pip',
            purl: this.buildPurl(name, version),
          });
        }
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
   * Extracts the version number from a pip version specifier.
   * "1.2.3" → "1.2.3"
   * "1.2.3,<2.0" → "1.2.3"
   */
  private extractVersion(spec: string): string {
    const cleaned = spec.split(',')[0].trim();
    return cleaned;
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
