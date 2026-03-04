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
 * With classifier: groupId:artifactId:type:classifier:version:scope
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
    // Read pom.xml to determine direct dependencies
    const pomPath = path.join(projectPath, 'pom.xml');
    const pomContent = await readFile(pomPath, 'utf-8').catch(() => null);
    const directDeps = pomContent ? this.parsePomDependencies(pomContent) : new Set<string>();

    // Strategy 1: Try pre-generated dependency-tree.txt
    const depTreePath = path.join(projectPath, 'dependency-tree.txt');
    if (existsSync(depTreePath)) {
      const content = await readFile(depTreePath, 'utf-8');
      const dependencies = this.parseDependencyList(content, directDeps);
      return this.buildResult(projectPath, depTreePath, dependencies);
    }

    // Strategy 2: Try running `mvn dependency:list`
    if (this.isMavenAvailable()) {
      const output = this.runMavenDependencyList(projectPath);
      const dependencies = this.parseDependencyList(output, directDeps);
      return this.buildResult(projectPath, pomPath, dependencies);
    }

    throw new LockfileParseError(
      pomPath,
      'Maven project detected (pom.xml found) but could not resolve dependencies. ' +
      'Either install Maven (`mvn` must be on $PATH) or pre-generate a dependency list:\n' +
      '  mvn dependency:list -DoutputFile=dependency-tree.txt -DappendOutput=true'
    );
  }

  /**
   * Parses pom.xml to extract direct dependency coordinates (groupId:artifactId).
   * This is a simple regex-based parser that handles standard dependency declarations.
   */
  private parsePomDependencies(pomContent: string): Set<string> {
    const directDeps = new Set<string>();

    // Match <dependency> blocks and extract groupId + artifactId
    // This regex handles multi-line dependency declarations
    const depBlockRegex = /<dependency>\s*([\s\S]*?)<\/dependency>/g;
    const groupIdRegex = /<groupId>\s*([^<]+)\s*<\/groupId>/;
    const artifactIdRegex = /<artifactId>\s*([^<]+)\s*<\/artifactId>/;

    let match;
    while ((match = depBlockRegex.exec(pomContent)) !== null) {
      const block = match[1];
      const groupMatch = block.match(groupIdRegex);
      const artifactMatch = block.match(artifactIdRegex);

      if (groupMatch && artifactMatch) {
        const groupId = groupMatch[1].trim();
        const artifactId = artifactMatch[1].trim();
        directDeps.add(`${groupId}:${artifactId}`);
      }
    }

    return directDeps;
  }

  /**
   * Parses Maven `dependency:list` output.
   *
   * Each dependency line has the format:
   *   groupId:artifactId:type:version:scope (5 parts)
   *   groupId:artifactId:type:classifier:version:scope (6 parts)
   *
   * Lines are typically indented with leading whitespace.
   */
  private parseDependencyList(content: string, directDeps: Set<string>): Dependency[] {
    const deps: Dependency[] = [];
    const seen = new Set<string>();

    for (const rawLine of content.split('\n')) {
      const line = rawLine.trim();
      if (!line) continue;

      // Split by colon - Maven coords use : as separator
      const parts = line.split(':');

      // Need at least 5 parts: groupId:artifactId:type:version:scope
      if (parts.length < 5) continue;

      const groupId = parts[0];
      const artifactId = parts[1];
      // parts[2] = type (jar, war, pom, etc.)

      // Handle optional classifier (6 parts) vs no classifier (5 parts)
      let version: string;
      let scope: string;

      if (parts.length >= 6) {
        // With classifier: groupId:artifactId:type:classifier:version:scope
        version = parts[4];
        scope = parts[5];
      } else {
        // Without classifier: groupId:artifactId:type:version:scope
        version = parts[3];
        scope = parts[4];
      }

      // Skip invalid entries
      if (!groupId || !artifactId || !version) continue;

      // Skip test-scoped dependencies
      if (scope === 'test') continue;

      const name = `${groupId}:${artifactId}`;

      // Deduplicate (same dep might appear multiple times)
      if (seen.has(name)) continue;
      seen.add(name);

      // Determine if direct by checking against pom.xml dependencies
      const isDirect = directDeps.has(name);

      deps.push({
        name,
        version,
        direct: isDirect,
        ecosystem: 'maven',
        purl: this.buildPurl(groupId, artifactId, version),
      });
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
