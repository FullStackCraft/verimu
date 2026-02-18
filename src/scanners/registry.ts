import type { DependencyScanner } from './scanner.interface.js';
import type { ScanResult } from '../core/types.js';
import { NpmScanner } from './npm/npm-scanner.js';
import { NugetScanner } from './nuget/nuget-scanner.js';
import { CargoScanner } from './cargo/cargo-scanner.js';
import { PipScanner } from './pip/pip-scanner.js';
import { MavenScanner } from './maven/maven-scanner.js';
import { GoScanner } from './go/go-scanner.js';
import { RubyScanner } from './ruby/ruby-scanner.js';
import { ComposerScanner } from './composer/composer-scanner.js';
import { NoLockfileError } from '../core/errors.js';
import { YarnScanner } from './yarn/yarn-scanner.js';
import { PnpmScanner } from './pnpm/pnpm-scanner.js';

/**
 * Registry of all available dependency scanners.
 * Auto-detects the correct scanner for a given project.
 */
export class ScannerRegistry {
  private scanners: DependencyScanner[];

  constructor() {
    this.scanners = [
      new NpmScanner(),
      new NugetScanner(),
      new CargoScanner(),
      new PipScanner(),
      new MavenScanner(),
      new GoScanner(),
      new RubyScanner(),
      new ComposerScanner(),
      new YarnScanner(),
      new PnpmScanner(),
    ];
  }

  /**
   * Auto-detects the project's ecosystem and scans dependencies.
   * Tries each registered scanner in order until one matches.
   */
  async detectAndScan(projectPath: string): Promise<ScanResult> {
    for (const scanner of this.scanners) {
      const lockfilePath = await scanner.detect(projectPath);
      if (lockfilePath) {
        return scanner.scan(projectPath, lockfilePath);
      }
    }
    throw new NoLockfileError(projectPath);
  }

  /** Returns a specific scanner by ecosystem name */
  getScanner(ecosystem: string): DependencyScanner | undefined {
    return this.scanners.find((s) => s.ecosystem === ecosystem);
  }

  /** Lists all registered ecosystems */
  listEcosystems(): string[] {
    return this.scanners.map((s) => s.ecosystem);
  }
}
