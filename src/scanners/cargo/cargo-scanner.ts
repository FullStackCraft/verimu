import type { DependencyScanner } from '../scanner.interface.js';
import type { Ecosystem, ScanResult } from '../../core/types.js';

/**
 * Rust / Cargo dependency scanner (STUB).
 *
 * TODO: Implement parsing of:
 *   - Cargo.lock (resolved dependency tree)
 *   - Cargo.toml (for direct dependency list)
 */
export class CargoScanner implements DependencyScanner {
  readonly ecosystem: Ecosystem = 'cargo';
  readonly lockfileNames = ['Cargo.lock'];

  async detect(_projectPath: string): Promise<string | null> {
    // TODO: Check for Cargo.lock
    return null;
  }

  async scan(_projectPath: string, _lockfilePath: string): Promise<ScanResult> {
    throw new Error('Cargo scanner not yet implemented. Coming soon.');
  }
}
