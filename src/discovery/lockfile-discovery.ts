import { readdir, stat } from 'fs/promises';
import { existsSync } from 'fs';
import path from 'path';
import type { DiscoveredProject, DiscoveryOptions, Ecosystem } from '../core/types.js';

/** Maps lockfile names to their ecosystem and scanner type */
const LOCKFILE_MAP: Record<string, { ecosystem: Ecosystem; scanner: string }> = {
  'pnpm-lock.yaml': { ecosystem: 'npm', scanner: 'pnpm' },
  'yarn.lock': { ecosystem: 'npm', scanner: 'yarn' },
  'package-lock.json': { ecosystem: 'npm', scanner: 'npm' },
  'deno.lock': { ecosystem: 'npm', scanner: 'deno' },
  'Cargo.lock': { ecosystem: 'cargo', scanner: 'cargo' },
  'go.sum': { ecosystem: 'go', scanner: 'go' },
  'Gemfile.lock': { ecosystem: 'ruby', scanner: 'ruby' },
  'composer.lock': { ecosystem: 'composer', scanner: 'composer' },
  'packages.lock.json': { ecosystem: 'nuget', scanner: 'nuget' },
  'poetry.lock': { ecosystem: 'poetry', scanner: 'poetry' },
  'uv.lock': { ecosystem: 'uv', scanner: 'uv' },
  'Pipfile.lock': { ecosystem: 'pip', scanner: 'pip' },
  'requirements.txt': { ecosystem: 'pip', scanner: 'pip' },
  'pom.xml': { ecosystem: 'maven', scanner: 'maven' },
};

/** Directories that should always be excluded from discovery */
const DEFAULT_EXCLUDES = [
  'node_modules',
  '.git',
  '.hg',
  '.svn',
  'vendor',
  'target',
  'dist',
  'build',
  '.next',
  '.nuxt',
  '__pycache__',
  '.venv',
  'venv',
  '.tox',
  'coverage',
  '.cache',
  'out',
  '.output',
];

interface WalkOptions {
  excludePatterns: string[];
  maxDepth: number;
  currentDepth: number;
}

export class LockfileDiscovery {
  private lockfileNames = Object.keys(LOCKFILE_MAP);

  /**
   * Discovers all lockfiles recursively starting from rootPath.
   * Returns a list of projects that can be scanned.
   */
  async discover(options: DiscoveryOptions): Promise<DiscoveredProject[]> {
    const { rootPath, exclude, maxDepth } = options;

    const absoluteRoot = path.resolve(rootPath);
    const discovered: DiscoveredProject[] = [];

    // Build exclude patterns (defaults + user-provided)
    const excludePatterns = this.buildExcludePatterns(exclude);

    // Recursive directory walker
    await this.walkDirectory(absoluteRoot, absoluteRoot, discovered, {
      excludePatterns,
      maxDepth: maxDepth ?? Infinity,  //not set, infinite for now, can add as a cli-flag later if needed
      currentDepth: 0,
    });

    // Sort by path for consistent output
    discovered.sort((a, b) => a.relativePath.localeCompare(b.relativePath));

    return discovered;
  }

  /**
   * Recursively walks directories looking for lockfiles.
   * Stops descending into a directory once a lockfile is found
   * (to avoid scanning nested node_modules, etc.)
   */
  private async walkDirectory(
    currentPath: string,
    rootPath: string,
    results: DiscoveredProject[],
    options: WalkOptions
  ): Promise<void> {
    const { excludePatterns, maxDepth, currentDepth } = options;

    // Check depth limit
    if (currentDepth > maxDepth) return;

    // Get relative path for pattern matching
    const relativePath = path.relative(rootPath, currentPath) || '.';

    // Check if this path should be excluded
    if (this.matchesAnyPattern(relativePath, excludePatterns)) {
      return;
    }

    // Check for lockfiles in current directory
    const foundLockfile = await this.findLockfileInDir(currentPath);

    if (foundLockfile) {
      results.push({
        projectPath: currentPath,
        relativePath,
        lockfile: {
          name: foundLockfile.name,
          path: path.join(currentPath, foundLockfile.name),
        },
        ecosystem: foundLockfile.ecosystem,
        scannerType: foundLockfile.scanner,
      });

      // Don't descend further - we found a project root
      return;
    }

    // No lockfile found, continue descending
    let entries: string[];
    try {
      entries = await readdir(currentPath);
    } catch {
      return; // Permission denied or other error
    }

    // Process subdirectories
    for (const entry of entries) {
      const entryPath = path.join(currentPath, entry);

      try {
        const stats = await stat(entryPath);

        if (stats.isDirectory()) {
          // Quick exclude check on directory name
          if (this.isDefaultExclude(entry)) continue;

          await this.walkDirectory(entryPath, rootPath, results, {
            ...options,
            currentDepth: currentDepth + 1,
          });
        }
      } catch {
        // Skip entries we can't stat
      }
    }
  }

  /**
   * Looks for a lockfile in the given directory.
   * Returns the first match in priority order.
   */
  private async findLockfileInDir(
    dirPath: string
  ): Promise<{ name: string; ecosystem: Ecosystem; scanner: string } | null> {
    // Priority order: specific lockfiles first, generic last
    const priorityOrder = [
      'pnpm-lock.yaml',
      'yarn.lock',
      'package-lock.json',
      'deno.lock',
      'Cargo.lock',
      'go.sum',
      'poetry.lock',
      'uv.lock',
      'Pipfile.lock',
      'composer.lock',
      'Gemfile.lock',
      'packages.lock.json',
      'pom.xml',
      'requirements.txt',
    ];

    for (const lockfileName of priorityOrder) {
      const lockfilePath = path.join(dirPath, lockfileName);
      if (existsSync(lockfilePath)) {
        const info = LOCKFILE_MAP[lockfileName];
        return { name: lockfileName, ...info };
      }
    }

    return null;
  }

  /**
   * Builds exclude patterns from user input + defaults.
   */
  private buildExcludePatterns(userExcludes?: string[]): string[] {
    const patterns: string[] = [];

    // Add default excludes as patterns
    for (const dir of DEFAULT_EXCLUDES) {
      patterns.push(`**/${dir}`);
      patterns.push(`**/${dir}/**`);
    }

    // Add user excludes
    if (userExcludes) {
      patterns.push(...userExcludes);
    }

    return patterns;
  }

  /**
   * Quick check if a directory name is in the default exclude list.
   */
  private isDefaultExclude(dirName: string): boolean {
    return DEFAULT_EXCLUDES.includes(dirName);
  }

  /**
   * Checks if a path matches any of the given glob patterns.
   * Uses simple glob matching (supports *, **, ?).
   */
  private matchesAnyPattern(relativePath: string, patterns: string[]): boolean {
    // Normalize path separators for cross-platform
    const normalized = relativePath.replace(/\\/g, '/');

    for (const pattern of patterns) {
      if (this.matchGlob(normalized, pattern)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Simple glob matcher supporting:
   * - * (matches any characters except /)
   * - ** (matches any characters including /)
   * - ? (matches single character)
   */
  private matchGlob(str: string, pattern: string): boolean {
    // Convert glob to regex
    let regex = pattern
      .replace(/\\/g, '/')
      .replace(/[.+^${}()|[\]\\]/g, '\\$&') // Escape special regex chars
      .replace(/\*\*/g, '{{GLOBSTAR}}') // Temp placeholder
      .replace(/\*/g, '[^/]*') // * matches non-slash
      .replace(/{{GLOBSTAR}}/g, '.*') // ** matches anything
      .replace(/\?/g, '.'); // ? matches single char

    // Anchor the pattern
    regex = `^${regex}$`;

    return new RegExp(regex).test(str);
  }
}
