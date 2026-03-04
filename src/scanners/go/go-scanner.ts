import { readFile } from 'fs/promises';
import { existsSync } from 'fs';
import path from 'path';
import type { DependencyScanner } from '../scanner.interface.js';
import type { Dependency, Ecosystem, ScanResult } from '../../core/types.js';
import { LockfileParseError } from '../../core/errors.js';

/**
 * Go module dependency scanner.
 *
 * Parses `go.sum` to extract the full resolved dependency list, and
 * cross-references `go.mod` to distinguish direct vs indirect (transitive)
 * dependencies.
 *
 * go.sum format (one or two lines per module):
 * ```
 * github.com/gin-gonic/gin v1.9.1 h1:abc123...=
 * github.com/gin-gonic/gin v1.9.1/go.mod h1:def456...=
 * ```
 *
 * Lines ending in `/go.mod` are checksums of the module's go.mod file —
 * we skip those and only keep the `h1:` lines (source archive checksums).
 *
 * go.mod `require` block format:
 * ```
 * require (
 *     github.com/gin-gonic/gin v1.9.1
 *     golang.org/x/text v0.14.0 // indirect
 * )
 * ```
 *
 * Dependencies marked `// indirect` are transitive.
 */
export class GoScanner implements DependencyScanner {
  readonly ecosystem: Ecosystem = 'go';
  readonly lockfileNames = ['go.sum'];

  async detect(projectPath: string): Promise<string | null> {
    const goSumPath = path.join(projectPath, 'go.sum');
    return existsSync(goSumPath) ? goSumPath : null;
  }

  async scan(projectPath: string, lockfilePath: string): Promise<ScanResult> {
    const [goSumRaw, goModRaw] = await Promise.all([
      readFile(lockfilePath, 'utf-8'),
      readFile(path.join(projectPath, 'go.mod'), 'utf-8').catch(() => null),
    ]);

    const { directNames, indirectNames } = goModRaw
      ? this.parseGoMod(goModRaw)
      : { directNames: new Set<string>(), indirectNames: new Set<string>() };

    const dependencies = this.parseGoSum(goSumRaw, lockfilePath, directNames, indirectNames);

    return {
      projectPath,
      ecosystem: 'go',
      dependencies,
      lockfilePath,
      scannedAt: new Date().toISOString(),
    };
  }

  /**
   * Parses go.sum and extracts unique module dependencies.
   *
   * Each module may appear twice in go.sum (once for the source archive,
   * once for go.mod). We deduplicate by module path + version, keeping
   * only the `h1:` entry (not the `/go.mod` entry).
   */
  private parseGoSum(
    content: string,
    lockfilePath: string,
    directNames: Set<string>,
    indirectNames: Set<string>,
  ): Dependency[] {
    const depMap = new Map<string, Dependency>();

    for (const rawLine of content.split('\n')) {
      const line = rawLine.trim();
      if (!line) continue;

      // Format: "module version hash"
      const parts = line.split(/\s+/);
      if (parts.length < 3) continue;

      const modulePath = parts[0];
      let version = parts[1];

      // Skip /go.mod checksum lines
      if (version.endsWith('/go.mod')) continue;

      // Strip any +incompatible suffix for cleaner versions
      version = version.replace(/\+incompatible$/, '');

      const key = `${modulePath}@${version}`;
      if (depMap.has(key)) continue;

      // Determine direct/indirect from go.mod data
      // If go.mod is available: explicit direct or not marked indirect = direct
      // If go.mod is not available: default to direct (conservative)
      const isDirect = directNames.size > 0 || indirectNames.size > 0
        ? directNames.has(modulePath) || (!indirectNames.has(modulePath) && !directNames.has(modulePath) ? false : directNames.has(modulePath))
        : true;

      depMap.set(key, {
        name: modulePath,
        version,
        direct: isDirect,
        ecosystem: 'go',
        purl: this.buildPurl(modulePath, version),
      });
    }

    return Array.from(depMap.values());
  }

  /**
   * Parses go.mod to extract direct and indirect dependency names.
   *
   * Handles both single-line and block `require` directives:
   * ```
   * require github.com/pkg/errors v0.9.1
   *
   * require (
   *     github.com/gin-gonic/gin v1.9.1
   *     golang.org/x/text v0.14.0 // indirect
   * )
   * ```
   */
  private parseGoMod(content: string): { directNames: Set<string>; indirectNames: Set<string> } {
    const directNames = new Set<string>();
    const indirectNames = new Set<string>();

    let inRequireBlock = false;

    for (const rawLine of content.split('\n')) {
      const line = rawLine.trim();

      // Single-line require: `require github.com/pkg/errors v0.9.1`
      if (line.startsWith('require ') && !line.includes('(')) {
        const match = line.match(/^require\s+(\S+)\s+\S+(.*)$/);
        if (match) {
          const modulePath = match[1];
          const rest = match[2];
          if (rest.includes('// indirect')) {
            indirectNames.add(modulePath);
          } else {
            directNames.add(modulePath);
          }
        }
        continue;
      }

      // Start of require block
      if (line === 'require (' || line.startsWith('require (')) {
        inRequireBlock = true;
        continue;
      }

      // End of require block
      if (inRequireBlock && line === ')') {
        inRequireBlock = false;
        continue;
      }

      // Inside require block
      if (inRequireBlock && line && !line.startsWith('//')) {
        const match = line.match(/^(\S+)\s+\S+(.*)$/);
        if (match) {
          const modulePath = match[1];
          const rest = match[2];
          if (rest.includes('// indirect')) {
            indirectNames.add(modulePath);
          } else {
            directNames.add(modulePath);
          }
        }
      }
    }

    return { directNames, indirectNames };
  }

  /**
   * Builds a purl for a Go module.
   *
   * Per purl spec, the type is "golang" and the module path
   * uses `/` separators (no encoding needed for path segments).
   *
   * Example: `pkg:golang/github.com/gin-gonic/gin@v1.9.1`
   */
  private buildPurl(modulePath: string, version: string): string {
    return `pkg:golang/${modulePath}@${version}`;
  }
}
