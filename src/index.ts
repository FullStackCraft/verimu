// ─── Primary API ────────────────────────────────────────────────
//
//   import { scan, generateSbom, shouldFailCi } from 'verimu'
//

export { generateSbom } from './generate-sbom.js';
export { scan, shouldFailCi, printReport } from './scan.js';

// ─── Types ──────────────────────────────────────────────────────

export type {
  // generateSbom() types
  GenerateSbomInput,
  GenerateSbomResult,
  SbomDependency,

  // scan() types
  Dependency,
  ScanResult,
  Sbom,
  SbomFormat,
  Severity,
  Vulnerability,
  VulnerabilitySource,
  CveCheckResult,
  VerimuReport,
  VerimuConfig,
  Ecosystem,
  CiProvider,
} from './core/types.js';

// ─── Errors ─────────────────────────────────────────────────────

export {
  VerimuError,
  NoLockfileError,
  LockfileParseError,
  CveSourceError,
  ApiKeyRequiredError,
} from './core/errors.js';

// ─── Advanced / Internal ────────────────────────────────────────
// For users who need fine-grained control over individual steps.

export { NpmScanner } from './scanners/npm/npm-scanner.js';
export { ScannerRegistry } from './scanners/registry.js';
export { CycloneDxGenerator } from './sbom/cyclonedx.js';
export { OsvSource } from './cve/osv.js';
export { CveAggregator } from './cve/aggregator.js';
export { ConsoleReporter } from './reporters/console.js';
