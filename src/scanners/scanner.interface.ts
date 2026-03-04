import type { ScanResult, Ecosystem } from '../core/types.js';

/**
 * Interface for language/ecosystem-specific dependency scanners.
 *
 * To add a new ecosystem (e.g., C#/NuGet):
 *   1. Create a new directory: scanners/nuget/
 *   2. Implement this interface
 *   3. Register it in scanners/registry.ts
 */
export interface DependencyScanner {
  /** The ecosystem this scanner handles */
  readonly ecosystem: Ecosystem;

  /** Lockfile names this scanner looks for (in priority order) */
  readonly lockfileNames: string[];

  /**
   * Detects whether this scanner can handle the given project.
   * Returns the path to the lockfile if found, null otherwise.
   */
  detect(projectPath: string): Promise<string | null>;

  /**
   * Scans the project and returns all resolved dependencies.
   * Should only be called after detect() returns a non-null path.
   */
  scan(projectPath: string, lockfilePath: string): Promise<ScanResult>;
}
