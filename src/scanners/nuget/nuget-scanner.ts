import type { DependencyScanner } from '../scanner.interface.js';
import type { Ecosystem, ScanResult } from '../../core/types.js';

/**
 * C# / NuGet dependency scanner (STUB).
 *
 * TODO: Implement parsing of:
 *   - packages.lock.json (NuGet lock file)
 *   - *.csproj files (for direct dependency list)
 */
export class NugetScanner implements DependencyScanner {
  readonly ecosystem: Ecosystem = 'nuget';
  readonly lockfileNames = ['packages.lock.json'];

  async detect(_projectPath: string): Promise<string | null> {
    // TODO: Check for packages.lock.json
    return null;
  }

  async scan(_projectPath: string, _lockfilePath: string): Promise<ScanResult> {
    throw new Error('NuGet scanner not yet implemented. Coming soon.');
  }
}
