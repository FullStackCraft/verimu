import { readFile } from 'fs/promises';
import { existsSync } from 'fs';
import path from 'path';
import type { DependencyScanner } from '../scanner.interface.js';
import type { Dependency, Ecosystem, ScanResult } from '../../core/types.js';
import { LockfileParseError } from '../../core/errors.js';

/**
 * Rust / Cargo dependency scanner.
 *
 * Parses `Cargo.lock` (TOML format) to extract the full resolved
 * dependency tree. Reads `Cargo.toml` to determine which packages
 * are direct dependencies vs transitive.
 *
 * Cargo.lock format (v3):
 * ```toml
 * [[package]]
 * name = "serde"
 * version = "1.0.195"
 * source = "registry+https://github.com/rust-lang/crates.io-index"
 * checksum = "abc123..."
 * dependencies = [
 *   "serde_derive",
 * ]
 * ```
 *
 * Note: We use a simple TOML parser since Cargo.lock has a very
 * regular structure (just [[package]] entries). No need for a full
 * TOML library.
 */
export class CargoScanner implements DependencyScanner {
  readonly ecosystem: Ecosystem = 'cargo';
  readonly lockfileNames = ['Cargo.lock'];

  async detect(projectPath: string): Promise<string | null> {
    const lockfilePath = path.join(projectPath, 'Cargo.lock');
    return existsSync(lockfilePath) ? lockfilePath : null;
  }

  async scan(projectPath: string, lockfilePath: string): Promise<ScanResult> {
    const [lockfileRaw, cargoTomlRaw] = await Promise.all([
      readFile(lockfilePath, 'utf-8'),
      readFile(path.join(projectPath, 'Cargo.toml'), 'utf-8').catch(() => null),
    ]);

    const packages = this.parseLockfile(lockfileRaw, lockfilePath);
    const directNames = cargoTomlRaw ? this.parseCargoToml(cargoTomlRaw) : new Set<string>();

    // The first [[package]] is typically the root project — skip it
    const rootName = packages.length > 0 ? packages[0].name : null;

    const dependencies: Dependency[] = [];
    for (const pkg of packages) {
      // Skip the root project itself
      if (pkg.name === rootName && pkg.source === undefined) continue;

      dependencies.push({
        name: pkg.name,
        version: pkg.version,
        direct: directNames.has(pkg.name),
        ecosystem: 'cargo',
        purl: this.buildPurl(pkg.name, pkg.version),
      });
    }

    return {
      projectPath,
      ecosystem: 'cargo',
      dependencies,
      lockfilePath,
      scannedAt: new Date().toISOString(),
    };
  }

  /**
   * Parses Cargo.lock by splitting on [[package]] blocks.
   * This is a lightweight parser that handles the regular structure
   * of Cargo.lock without needing a full TOML parser.
   */
  private parseLockfile(content: string, lockfilePath: string): CargoPackage[] {
    const packages: CargoPackage[] = [];
    const blocks = content.split(/^\[\[package\]\]$/m);

    for (const block of blocks) {
      if (!block.trim()) continue;

      const name = this.extractField(block, 'name');
      const version = this.extractField(block, 'version');
      const source = this.extractField(block, 'source');

      if (name && version) {
        packages.push({ name, version, source: source || undefined });
      }
    }

    if (packages.length === 0 && content.includes('[[package]]')) {
      throw new LockfileParseError(lockfilePath, 'Failed to parse any packages from Cargo.lock');
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
   * Parses Cargo.toml to extract direct dependency names.
   * Looks for [dependencies] and [dev-dependencies] sections.
   */
  private parseCargoToml(content: string): Set<string> {
    const directNames = new Set<string>();
    let inDepsSection = false;

    for (const rawLine of content.split('\n')) {
      const line = rawLine.trim();

      // Detect section headers
      if (line.startsWith('[')) {
        inDepsSection =
          line === '[dependencies]' ||
          line === '[dev-dependencies]' ||
          line === '[build-dependencies]';
        continue;
      }

      if (inDepsSection && line && !line.startsWith('#')) {
        // Extract package name from "name = ..." or "name = { version = ... }"
        const match = line.match(/^([a-zA-Z0-9_-]+)\s*=/);
        if (match) {
          directNames.add(match[1]);
        }
      }
    }

    return directNames;
  }

  /**
   * Builds a purl for a Cargo (crates.io) package.
   */
  private buildPurl(name: string, version: string): string {
    return `pkg:cargo/${name}@${version}`;
  }
}

// ─── Internal types ──────────────────────────────────────────────

interface CargoPackage {
  name: string;
  version: string;
  source?: string;
}
