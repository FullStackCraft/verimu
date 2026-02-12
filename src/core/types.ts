/**
 * Core types for the Verimu scanning pipeline.
 *
 * These types flow through the system:
 *   Lockfile → Scanner → Dependency[] → SbomGenerator → SBOM
 *                                     → CveSource → Vulnerability[]
 */

// ─── Dependency Detection ───────────────────────────────────────

/** Supported package ecosystems */
export type Ecosystem = 'npm' | 'nuget' | 'cargo' | 'maven' | 'pip' | 'go' | 'ruby';

/** Supported CI/CD providers */
export type CiProvider = 'github' | 'gitlab' | 'bitbucket';

/** A single resolved dependency from a lockfile */
export interface Dependency {
  /** Package name (e.g., "express", "lodash") */
  name: string;
  /** Exact resolved version (e.g., "4.18.2") */
  version: string;
  /** Whether this is a direct dependency (in package.json) or transitive */
  direct: boolean;
  /** The ecosystem this dependency belongs to */
  ecosystem: Ecosystem;
  /** Package URL (purl) — standard identifier for SBOMs */
  purl: string;
}

/** Result of scanning a project's dependencies */
export interface ScanResult {
  /** Path to the project root that was scanned */
  projectPath: string;
  /** Ecosystem detected */
  ecosystem: Ecosystem;
  /** All resolved dependencies (direct + transitive) */
  dependencies: Dependency[];
  /** Path to the lockfile that was parsed */
  lockfilePath: string;
  /** Timestamp of when the scan was performed */
  scannedAt: string;
}

// ─── SBOM ───────────────────────────────────────────────────────

/** Supported SBOM output formats */
export type SbomFormat = 'cyclonedx-json' | 'cyclonedx-xml' | 'spdx-json';

/** A generated Software Bill of Materials */
export interface Sbom {
  /** The format of this SBOM */
  format: SbomFormat;
  /** The spec version (e.g., "1.5" for CycloneDX) */
  specVersion: string;
  /** Serialized SBOM content (JSON string or XML string) */
  content: string;
  /** Number of components in the SBOM */
  componentCount: number;
  /** Timestamp of generation */
  generatedAt: string;
}

// ─── Vulnerability / CVE ────────────────────────────────────────

/** Severity levels aligned with CVSS v3 */
export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';

/** A single known vulnerability */
export interface Vulnerability {
  /** CVE identifier (e.g., "CVE-2024-1234") or advisory ID */
  id: string;
  /** Aliases (e.g., GHSA-xxxx, EUVD-2025-xxxx) */
  aliases: string[];
  /** Human-readable summary */
  summary: string;
  /** Severity level */
  severity: Severity;
  /** CVSS score (0-10), if available */
  cvssScore?: number;
  /** The package this vulnerability affects */
  packageName: string;
  /** The ecosystem of the affected package */
  ecosystem: Ecosystem;
  /** Version range that is affected (human-readable) */
  affectedVersionRange?: string;
  /** Fixed version, if available */
  fixedVersion?: string;
  /** Whether this is actively exploited (from CISA KEV) */
  exploitedInWild: boolean;
  /** Source that reported this vulnerability */
  source: VulnerabilitySource;
  /** URL for more information */
  referenceUrl?: string;
  /** Date the vulnerability was published */
  publishedAt?: string;
}

/** Sources we check for vulnerabilities */
export type VulnerabilitySource = 'osv' | 'nvd' | 'euvd' | 'cisa-kev' | 'github-advisory';

/** Result of checking dependencies for vulnerabilities */
export interface CveCheckResult {
  /** Vulnerabilities found, grouped by dependency */
  vulnerabilities: Vulnerability[];
  /** Sources that were successfully queried */
  sourcesQueried: VulnerabilitySource[];
  /** Sources that failed (with error message) */
  sourceErrors: { source: VulnerabilitySource; error: string }[];
  /** Total time taken for all checks (ms) */
  checkDurationMs: number;
}

// ─── Scan Pipeline Output ───────────────────────────────────────

/** Complete output of a Verimu scan */
export interface VerimuReport {
  /** Project info */
  project: {
    path: string;
    ecosystem: Ecosystem;
    dependencyCount: number;
  };
  /** Generated SBOM */
  sbom: Sbom;
  /** CVE check results */
  cveCheck: CveCheckResult;
  /** Overall summary */
  summary: {
    totalDependencies: number;
    totalVulnerabilities: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    exploitedInWild: number;
  };
  /** Timestamp */
  generatedAt: string;
}

// ─── Configuration ──────────────────────────────────────────────

/** Configuration for a Verimu scan */
export interface VerimuConfig {
  /** Path to the project to scan */
  projectPath: string;
  /** Where to write the SBOM file (default: ./sbom.cdx.json) */
  sbomOutput?: string;
  /** SBOM format (default: cyclonedx-json) */
  sbomFormat?: SbomFormat;
  /** Minimum severity to report (default: LOW) */
  severityThreshold?: Severity;
  /** Whether to fail CI on vulnerabilities at or above threshold */
  failOnSeverity?: boolean;
  /** API key for Verimu backend (enables snapshot upload + monitoring) */
  apiKey?: string;
  /** Verimu API base URL */
  apiBaseUrl?: string;
  /** Skip CVE checking (just generate SBOM) */
  skipCveCheck?: boolean;
}

// ─── generateSbom() Input / Output ─────────────────────────────

/** Input for the pure `generateSbom()` function */
export interface GenerateSbomInput {
  /** Name of the project / root component */
  projectName: string;
  /** Version of the project / root component */
  projectVersion?: string;
  /** Resolved dependencies to include in the SBOM */
  dependencies: SbomDependency[];
}

/**
 * A dependency entry for `generateSbom()`.
 *
 * Simplified compared to the full `Dependency` type — only requires
 * name, version, and ecosystem. PURL is auto-generated if omitted.
 */
export interface SbomDependency {
  /** Package name (e.g., "express", "@types/node") */
  name: string;
  /** Exact resolved version (e.g., "4.18.2") */
  version: string;
  /** Package ecosystem */
  ecosystem: Ecosystem;
  /** Whether this is a direct dependency (default: true) */
  direct?: boolean;
  /** Package URL — auto-generated if omitted */
  purl?: string;
}

/** Output of the pure `generateSbom()` function */
export interface GenerateSbomResult {
  /** The SBOM as a parsed JavaScript object */
  sbom: Record<string, unknown>;
  /** The SBOM as a formatted JSON string */
  content: string;
  /** Number of components in the SBOM */
  componentCount: number;
  /** CycloneDX spec version used */
  specVersion: string;
  /** ISO timestamp of generation */
  generatedAt: string;
}
