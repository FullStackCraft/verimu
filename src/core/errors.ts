/** Base error for all Verimu errors */
export class VerimuError extends Error {
  constructor(message: string, public readonly code: string) {
    super(message);
    this.name = 'VerimuError';
  }
}

/** Thrown when no supported lockfile is found */
export class NoLockfileError extends VerimuError {
  constructor(projectPath: string) {
    super(
      `No supported lockfile found in ${projectPath}. ` +
        `Supported: package-lock.json (npm), packages.lock.json (NuGet), Cargo.lock (Rust)`,
      'NO_LOCKFILE'
    );
    this.name = 'NoLockfileError';
  }
}

/** Thrown when lockfile parsing fails */
export class LockfileParseError extends VerimuError {
  constructor(lockfilePath: string, reason: string) {
    super(`Failed to parse ${lockfilePath}: ${reason}`, 'LOCKFILE_PARSE_ERROR');
    this.name = 'LockfileParseError';
  }
}

/** Thrown when a CVE source query fails */
export class CveSourceError extends VerimuError {
  constructor(source: string, reason: string) {
    super(`CVE source "${source}" failed: ${reason}`, 'CVE_SOURCE_ERROR');
    this.name = 'CveSourceError';
  }
}

/** Thrown when API key is required but missing */
export class ApiKeyRequiredError extends VerimuError {
  constructor(feature: string) {
    super(
      `API key required for "${feature}". Get one at https://verimu.com/dashboard`,
      'API_KEY_REQUIRED'
    );
    this.name = 'ApiKeyRequiredError';
  }
}
