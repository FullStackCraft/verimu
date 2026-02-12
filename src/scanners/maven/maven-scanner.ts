import { readFile } from 'fs/promises';
import { existsSync } from 'fs';
import { execSync } from 'child_process';
import path from 'path';
import type { DependencyScanner } from '../scanner.interface.js';
import type { Dependency, Ecosystem, ScanResult } from '../../core/types.js';
import { LockfileParseError } from '../../core/errors.js';

/**
 * Java / Maven dependency scanner.
 *
 * Maven doesn't have a lockfile. This scanner uses two strategies:
 *
 *   1. **Primary (auto)**: If `mvn` is on `$PATH`, runs
 *      `mvn dependency:list -DoutputType=text` to get the resolved
 *      dependency tree including transitive dependencies.
 *
 *   2. **Fallback (pre-generated)**: Looks for a `dependency-tree.txt`
 *      file in the project root. Users can generate this with:
 *      ```
 *      mvn dependency:list -DoutputFile=dependency-tree.txt -DoutputType=text
 *      ```
 *
 * The scanner detects a Maven project by the presence of `pom.xml`.
 *
 * Maven dependency:list output format (one per line):
 * ```
 *    com.google.guava:guava:jar:32.1.3-jre:compile
 *    org.slf4j:slf4j-api:jar:2.0.9:compile
 *    junit:junit:jar:4.13.2:test
 * ```
 * Fields: groupId:artifactId:type:version:scope
 */
export class MavenScanner implements DependencyScanner {
  readonly ecosystem: Ecosystem = 'maven';
  readonly lockfileNames = ['pom.xml'];

  /** Allow injection for testing */
  private execSyncFn: typeof execSync;

  constructor(execSyncImpl?: typeof execSync) {
    this.execSyncFn = execSyncImpl ?? execSync;
  }

  async detect(projectPath: string): Promise<string | null> {
    const pomPath = path.join(projectPath, 'pom.xml');
    return existsSync(pomPath) ? pomPath : null;
  }

  async scan(projectPath: string, _lockfilePath: string): Promise<ScanResult> {
    // Strategy 1: Try pre-generated dependency-tree.txt
    const depTreePath = path.join(projectPath, 'dependency-tree.txt');
    if (existsSync(depTreePath)) {
      const content = await readFile(depTreePath, 'utf-8');
      const dependencies = this.parseDependencyList(content, depTreePath);
      return this.buildResult(projectPath, depTreePath, dependencies);
    }

    // Strategy 2: Try running `mvn dependency:list`
    if (this.isMavenAvailable()) {
      const output = this.runMavenDependencyList(projectPath);
      const dependencies = this.parseDependencyList(output, 'mvn dependency:list');
      return this.buildResult(projectPath, path.join(projectPath, 'pom.xml'), dependencies);
    }

    throw new LockfileParseError(
      path.join(projectPath, 'pom.xml'),
      'Maven project detected (pom.xml found) but could not resolve dependencies. ' +
        'Either install Maven (`mvn` must be on $PATH) or pre-generate a dependency list:\n' +
        '  mvn dependency:list -DoutputFile=dependency-tree.txt -DappendOutput=true'
    );
  }

  /**
   * Parses Maven `dependency:list` output.
   *
   * Each dependency line has the format:
   *   groupId:artifactId:type:version:scope
   *   groupId:artifactId:type:classifier:version:scope
   *
   * Lines are typically indented with leading whitespace.
   */
  private parseDependencyList(content: string, source: string): Dependency[] {
    const deps: Dependency[] = [];
    const depPattern = /^\s*([a-zA-Z0-9._-]+):([a-zA-Z0-9._-]+):([a-z]+):(?:([a-zA-Z0-9._-]+):)?([a-zA-Z0-9._-]+):([a-z]+)/;

    for (const rawLine of content.split('\n')) {
      const line = rawLine.trim();
      if (!line) continue;

      const match = line.match(depPattern);
      if (match) {
        const groupId = match[1];
        const artifactId = match[2];
        // match[3] = type (jar, etc.)
        // match[4] = classifier (optional — may be undefined)
        const version = match[4] && match[5] ? match[5] : (match[4] ?? match[5]);
        const scope = match[4] && match[5] ? match[6] : (match[5] && match[6] ? match[6] : match[5]);

        // Re-parse more carefully: the regex groups shift with/without classifier
        const parts = line.split(':');
        if (parts.length >= 5) {
          const gId = parts[0].trim();
          const aId = parts[1];
          const ver = parts.length === 6 ? parts[4] : parts[3];
          const scp = parts.length === 6 ? parts[5] : parts[4];

          if (gId && aId && ver) {
            const name = `${gId}:${aId}`;
            deps.push({
              name,
              version: ver,
              direct: scp === 'compile' || scp === 'runtime' || scp === 'provided',
              ecosystem: 'maven',
              purl: this.buildPurl(gId, aId, ver),
            });
          }
        }
      }
    }

    return deps;
  }

  /** Checks if `mvn` is available on PATH */
  private isMavenAvailable(): boolean {
    try {
      this.execSyncFn('mvn --version', { stdio: 'pipe', timeout: 10_000 });
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Runs `mvn dependency:list` and returns the output.
   */
  private runMavenDependencyList(projectPath: string): string {
    try {
      const output = this.execSyncFn(
        'mvn dependency:list -DoutputType=text -DincludeScope=compile',
        {
          cwd: projectPath,
          stdio: 'pipe',
          timeout: 120_000, // 2 minute timeout
          encoding: 'utf-8',
        }
      );
      return output.toString();
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      throw new LockfileParseError(
        path.join(projectPath, 'pom.xml'),
        `Failed to run 'mvn dependency:list': ${message}`
      );
    }
  }

  /**
   * Builds a purl for a Maven package.
   * Format: pkg:maven/groupId/artifactId@version
   */
  private buildPurl(groupId: string, artifactId: string, version: string): string {
    return `pkg:maven/${groupId}/${artifactId}@${version}`;
  }

  private buildResult(
    projectPath: string,
    lockfilePath: string,
    dependencies: Dependency[]
  ): ScanResult {
    return {
      projectPath,
      ecosystem: 'maven',
      dependencies,
      lockfilePath,
      scannedAt: new Date().toISOString(),
    };
  }
}
