import { readFile } from 'fs/promises';
import { existsSync } from 'fs';
import path from 'path';
import type { DependencyScanner } from '../scanner.interface.js';
import type { Dependency, Ecosystem, ScanResult } from '../../core/types.js';
import { LockfileParseError } from '../../core/errors.js';

/**
 * Ruby dependency scanner (Bundler).
 *
 * Parses `Gemfile.lock` to extract the full resolved dependency list,
 * and cross-references the `DEPENDENCIES` section to distinguish
 * direct vs transitive gems.
 *
 * Gemfile.lock format:
 * ```
 * GEM
 *   remote: https://rubygems.org/
 *   specs:
 *     actioncable (7.1.2)
 *       actionpack (= 7.1.2)
 *       activesupport (= 7.1.2)
 *     rack (3.0.8)
 *
 * PLATFORMS
 *   ruby
 *
 * DEPENDENCIES
 *   puma (>= 5.0)
 *   rails (~> 7.1.2)
 *
 * BUNDLED WITH
 *   2.5.3
 * ```
 *
 * The `GEM > specs:` section lists all resolved gems with exact versions.
 * The `DEPENDENCIES` section lists direct gems (from the Gemfile).
 */
export class RubyScanner implements DependencyScanner {
  readonly ecosystem: Ecosystem = 'ruby';
  readonly lockfileNames = ['Gemfile.lock'];

  async detect(projectPath: string): Promise<string | null> {
    const lockfilePath = path.join(projectPath, 'Gemfile.lock');
    return existsSync(lockfilePath) ? lockfilePath : null;
  }

  async scan(projectPath: string, lockfilePath: string): Promise<ScanResult> {
    const content = await readFile(lockfilePath, 'utf-8');

    const specs = this.parseSpecs(content, lockfilePath);
    const directNames = this.parseDependencies(content);

    const dependencies: Dependency[] = specs.map(({ name, version }) => ({
      name,
      version,
      direct: directNames.has(name),
      ecosystem: 'ruby' as Ecosystem,
      purl: `pkg:gem/${name}@${version}`,
    }));

    return {
      projectPath,
      ecosystem: 'ruby',
      dependencies,
      lockfilePath,
      scannedAt: new Date().toISOString(),
    };
  }

  /**
   * Parses the GEM > specs section to extract all resolved gems.
   *
   * Gems at the top level of the specs section (indented 4 spaces) are
   * resolved packages. Their sub-dependencies (indented 6+ spaces) are
   * constraints, not separate entries — those sub-deps appear as their
   * own top-level spec entries elsewhere.
   *
   * Format: `    gem-name (1.2.3)`
   */
  private parseSpecs(
    content: string,
    lockfilePath: string,
  ): Array<{ name: string; version: string }> {
    const gems: Array<{ name: string; version: string }> = [];

    let inGemSection = false;
    let inSpecs = false;

    for (const rawLine of content.split('\n')) {
      const line = rawLine;

      // Detect section boundaries (lines with no leading whitespace)
      if (line.length > 0 && line[0] !== ' ') {
        if (line.startsWith('GEM')) {
          inGemSection = true;
          inSpecs = false;
          continue;
        }
        // Any other top-level section ends GEM
        inGemSection = false;
        inSpecs = false;
        continue;
      }

      if (inGemSection && line.trimStart().startsWith('specs:')) {
        inSpecs = true;
        continue;
      }

      if (!inSpecs) continue;

      // Top-level gems are indented exactly 4 spaces: "    gem-name (1.2.3)"
      // Sub-dependencies are indented 6+ spaces: "      dep-name (>= 1.0)"
      // We only want the 4-space entries (actual resolved packages)
      const match = line.match(/^ {4}(\S+)\s+\(([^)]+)\)$/);
      if (match) {
        const [, name, version] = match;
        gems.push({ name, version });
      }
    }

    if (gems.length === 0) {
      throw new LockfileParseError(
        lockfilePath,
        'No gems found in GEM specs section',
      );
    }

    return gems;
  }

  /**
   * Parses the DEPENDENCIES section to get direct dependency names.
   *
   * Format: `  gem-name (>= 1.0)` or `  gem-name`
   * The version constraint is optional and we only need the name.
   */
  private parseDependencies(content: string): Set<string> {
    const directNames = new Set<string>();
    let inDependencies = false;

    for (const rawLine of content.split('\n')) {
      const line = rawLine;

      // Section header (no leading space)
      if (line.length > 0 && line[0] !== ' ') {
        if (line.startsWith('DEPENDENCIES')) {
          inDependencies = true;
          continue;
        }
        if (inDependencies) break; // Next section → stop
        continue;
      }

      if (!inDependencies) continue;

      // Dependencies are indented 2 spaces: "  gem-name" or "  gem-name (>= 1.0)"
      // The ! suffix indicates a gem loaded from a specific source/path
      const match = line.match(/^ {2}(\S+?)!?\s*(?:\(|$)/);
      if (match) {
        directNames.add(match[1]);
      }
    }

    return directNames;
  }
}
