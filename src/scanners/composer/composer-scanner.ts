import { readFile } from 'fs/promises';
import { existsSync } from 'fs';
import path from 'path';
import type { DependencyScanner } from '../scanner.interface.js';
import type { Dependency, Ecosystem, ScanResult } from '../../core/types.js';
import { LockfileParseError } from '../../core/errors.js';

/**
 * PHP / Composer dependency scanner.
 *
 * Parses `composer.lock` for resolved packages and uses `composer.json`
 * (if present) to identify direct dependencies.
 */
export class ComposerScanner implements DependencyScanner {
  readonly ecosystem: Ecosystem = 'composer';
  readonly lockfileNames = ['composer.lock'];

  async detect(projectPath: string): Promise<string | null> {
    const lockfilePath = path.join(projectPath, 'composer.lock');
    return existsSync(lockfilePath) ? lockfilePath : null;
  }

  async scan(projectPath: string, lockfilePath: string): Promise<ScanResult> {
    const [lockRaw, manifestRaw] = await Promise.all([
      readFile(lockfilePath, 'utf-8'),
      readFile(path.join(projectPath, 'composer.json'), 'utf-8').catch(() => null),
    ]);

    const directNames = manifestRaw ? this.parseComposerManifest(manifestRaw) : null;
    const dependencies = this.parseComposerLock(lockRaw, lockfilePath, directNames);

    return {
      projectPath,
      ecosystem: 'composer',
      dependencies,
      lockfilePath,
      scannedAt: new Date().toISOString(),
    };
  }

  private parseComposerLock(
    content: string,
    lockfilePath: string,
    directNames: Set<string> | null
  ): Dependency[] {
    let lock: ComposerLock;
    try {
      lock = JSON.parse(content) as ComposerLock;
    } catch {
      throw new LockfileParseError(lockfilePath, 'Invalid JSON in composer.lock');
    }

    const allPackages = [...(lock.packages ?? []), ...(lock['packages-dev'] ?? [])];
    if (allPackages.length === 0) {
      throw new LockfileParseError(lockfilePath, 'No packages found in composer.lock');
    }

    return allPackages
      .filter((pkg) => pkg.name && pkg.version)
      .map((pkg) => ({
        name: pkg.name,
        version: this.normalizeVersion(pkg.version),
        direct: directNames ? directNames.has(pkg.name) : true,
        ecosystem: 'composer' as Ecosystem,
        purl: this.buildPurl(pkg.name, this.normalizeVersion(pkg.version)),
      }));
  }

  private parseComposerManifest(content: string): Set<string> {
    let manifest: ComposerManifest;
    try {
      manifest = JSON.parse(content) as ComposerManifest;
    } catch {
      return new Set<string>();
    }

    const names = new Set<string>();
    for (const section of [manifest.require ?? {}, manifest['require-dev'] ?? {}]) {
      for (const name of Object.keys(section)) {
        // Exclude platform constraints.
        if (name === 'php' || name.startsWith('ext-') || name.startsWith('lib-')) continue;
        names.add(name);
      }
    }

    return names;
  }

  private normalizeVersion(version: string): string {
    return version.trim();
  }

  private buildPurl(name: string, version: string): string {
    return `pkg:composer/${name}@${version}`;
  }
}

interface ComposerLock {
  packages?: ComposerPackage[];
  'packages-dev'?: ComposerPackage[];
}

interface ComposerPackage {
  name: string;
  version: string;
}

interface ComposerManifest {
  require?: Record<string, string>;
  'require-dev'?: Record<string, string>;
}

