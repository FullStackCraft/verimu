import type { ScanResult, Sbom, SbomFormat } from '../core/types.js';

/**
 * Interface for SBOM generators.
 * Each generator produces a specific format (CycloneDX, SPDX, etc.)
 */
export interface SbomGenerator {
  /** The format this generator produces */
  readonly format: SbomFormat;

  /** Generates an SBOM from scan results */
  generate(scanResult: ScanResult, toolVersion?: string): Sbom;
}
