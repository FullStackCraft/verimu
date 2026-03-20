// ─── Primary API ────────────────────────────────────────────────
//
//   import { scan, generateSbom, shouldFailCi } from 'verimu'
//

export { generateSbom } from './generate-sbom.js';
export { generateSpdxSbom } from './generate-spdx.js';
export { generateSwidTag } from './generate-swid.js';
export { scan, shouldFailCi, printReport, uploadToVerimu } from './scan.js';
export { detectSource } from './core/source.js';
export type { SbomSource } from './core/source.js';

// ─── Types ──────────────────────────────────────────────────────

export type {
  // generateSbom() types
  GenerateSbomInput,
  GenerateSbomResult,
  GenerateSpdxSbomResult,
  GenerateSwidTagResult,
  SbomDependency,

  // scan() types
  Dependency,
  ScanResult,
  Sbom,
  SbomArtifacts,
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

export type { UploadResult } from './scan.js';

// ─── Errors ─────────────────────────────────────────────────────

export {
  VerimuError,
  NoLockfileError,
  LockfileParseError,
  CveSourceError,
  ApiKeyRequiredError,
} from './core/errors.js';

// ─── API Client ─────────────────────────────────────────────────

export { VerimuApiClient } from './api/client.js';

// ─── Advanced / Internal ────────────────────────────────────────
// For users who need fine-grained control over individual steps.

export { NpmScanner } from './scanners/npm/npm-scanner.js';
export { NugetScanner } from './scanners/nuget/nuget-scanner.js';
export { PipScanner } from './scanners/pip/pip-scanner.js';
export { CargoScanner } from './scanners/cargo/cargo-scanner.js';
export { MavenScanner } from './scanners/maven/maven-scanner.js';
export { GoScanner } from './scanners/go/go-scanner.js';
export { RubyScanner } from './scanners/ruby/ruby-scanner.js';
export { ComposerScanner } from './scanners/composer/composer-scanner.js';
export { YarnScanner } from './scanners/yarn/yarn-scanner.js';
export { PnpmScanner } from './scanners/pnpm/pnpm-scanner.js';
export { DenoScanner } from './scanners/deno/deno-scanner.js';
export { ScannerRegistry } from './scanners/registry.js';
export { generateSbomArtifacts } from './sbom/artifacts.js';
export { CycloneDxGenerator } from './sbom/cyclonedx.js';
export { SpdxJsonGenerator } from './sbom/spdx.js';
export { SwidTagGenerator } from './sbom/swid.js';
export { OsvSource } from './cve/osv.js';
export { CveAggregator } from './cve/aggregator.js';
export { ConsoleReporter } from './reporters/console.js';
