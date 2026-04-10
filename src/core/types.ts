/**
 * Core types for the Verimu scanning pipeline.
 *
 * These types flow through the system:
 *   Lockfile → Scanner → Dependency[] → SbomGenerator → SBOM
 *                                     → CveSource → Vulnerability[]
 */

// ─── Dependency Detection ───────────────────────────────────────

/** Supported package ecosystems */
export type Ecosystem = 'npm' | 'nuget' | 'cargo' | 'maven' | 'pip' | 'poetry' | 'uv' | 'go' | 'ruby' | 'composer' | 'deno';

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

/** Supported software inventory output formats */
export type SbomFormat = 'cyclonedx-json' | 'cyclonedx-xml' | 'spdx-json' | 'swid-xml';

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

/** All software inventory artifacts generated for a scan */
export interface SbomArtifacts {
  /** Primary CRA-compatible SBOM used for backend parsing */
  cyclonedx: Sbom;
  /** SPDX 2.3 JSON document for interoperability */
  spdx: Sbom;
  /** Minimal SWID XML tag for root product identity */
  swid: Sbom;
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

// ─── Vulnerability Usage Context ───────────────────────────────

/** How confidently a vulnerable package is used in source code */
export type UsageContextStatus = 'direct_evidence' | 'indirect_no_evidence' | 'unsupported' | 'analysis_error';

/** Match categories for usage snippets */
export type UsageSnippetMatchKind =
  | 'import'
  | 'require'
  | 'dynamic_import'
  | 'export_from'
  | 'call';

/** A code snippet where a vulnerable package appears to be used */
export interface UsageSnippet {
  /** Project-relative path to the file */
  filePath: string;
  /** 1-based start line of the snippet in source file */
  startLine: number;
  /** 1-based end line of the snippet in source file */
  endLine: number;
  /** Snippet text including context lines */
  code: string;
  /** Kind of syntax match */
  matchKind: UsageSnippetMatchKind;
  /** Called symbol if this snippet is a call-site match */
  calledSymbol?: string;
  /** Confidence score in [0, 1] */
  confidence: number;
  /**
   * Which lines within `code` to highlight in the UI.
   * Both values are 0-indexed offsets into the `code` string's lines
   * (i.e. relative to `startLine`, not to the source file).
   * Example: if startLine=6 and the match is on source line 10,
   * highlight = [4, 4] (single-line) or [4, 6] (multi-line range).
   */
  highlight: [startOffset: number, endOffset: number];
}

/** Usage-context outcome for one vulnerability */
export interface UsageContextVulnerabilityFinding {
  /** Vulnerability identifier (CVE/GHSA/etc.) */
  vulnerabilityId: string;
  /** Package name that is vulnerable */
  packageName: string;
  /** Ecosystem the package belongs to */
  ecosystem: Ecosystem;
  /** Whether dependency scanner marked it as direct, if known */
  directDependency: boolean | null;
  /** Resolution status for this package usage */
  status: UsageContextStatus;
  /** Matched snippets for this vulnerable package */
  snippets: UsageSnippet[];
  /** Number of snippets in this finding */
  evidenceCount: number;
  /** Optional explanatory note */
  notes?: string;
}

/** LLM-friendly usage context payload for one vulnerability */
export interface UsageContextLlmPayload {
  vulnerability: {
    id: string;
    aliases: string[];
    severity: Severity;
    summary: string;
    affectedVersionRange?: string;
    fixedVersion?: string;
    referenceUrl?: string;
  };
  package: {
    name: string;
    ecosystem: Ecosystem;
    directDependency: boolean | null;
  };
  status: UsageContextStatus;
  evidenceCount: number;
  snippets: UsageSnippet[];
  notes?: string;
}

/** Analyzer-level status summary for one ecosystem */
export interface UsageContextEcosystemStatus {
  ecosystem: Ecosystem;
  analyzer: string;
  status: 'analyzed' | 'unsupported' | 'error';
  vulnerablePackages: number;
  snippetsFound: number;
  note?: string;
}

/** Non-fatal usage-context analysis error */
export interface UsageContextError {
  analyzer: string;
  ecosystem?: Ecosystem;
  packageName?: string;
  error: string;
}

/** Complete usage-context output for a scan */
export interface UsageContextResult {
  /** Whether usage analysis was executed */
  triggered: boolean;
  /** Scan duration in milliseconds */
  durationMs: number;
  /** Effective context lines setting (±N around each match) */
  numContextLines: number;
  /** Package-level snippet cap */
  maxSnippetsPerPackage: number;
  /** Global snippet cap */
  maxSnippetsTotal: number;
  /** Total snippets emitted */
  totalSnippets: number;
  /** Artifact path if written to disk */
  artifactPath?: string;
  /** Per-vulnerability findings */
  packageFindings: UsageContextVulnerabilityFinding[];
  /** Ecosystem-level analyzer status */
  ecosystemStatus: UsageContextEcosystemStatus[];
  /** Non-fatal analysis errors */
  errors: UsageContextError[];
  /** LLM-ready payload entries */
  llmPayload: UsageContextLlmPayload[];
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
  /** All generated software inventory artifacts (CycloneDX + SPDX + SWID) */
  artifacts?: SbomArtifacts;
  /** CVE check results */
  cveCheck: CveCheckResult;
  /** Optional usage-context analysis for vulnerable packages */
  usageContext?: UsageContextResult;
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
  /** Where to write the CycloneDX SBOM file (default: ./sbom.cdx.json) */
  sbomOutput?: string;
  /** Reserved for future per-format selection (currently all formats are generated) */
  sbomFormat?: SbomFormat;
  /** CycloneDX spec version to generate (default: '1.7') */
  cyclonedxVersion?: '1.4' | '1.5' | '1.6' | '1.7';
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
  /** Optional context lines around usage snippets (default: 4, clamped to 0..20) */
  numContextLines?: number;
  /** Optional group name to associate this project with others in the dashboard */
  groupName?: string;
  /** Optional explicit project name to use for backend upsert/upload */
  uploadProjectName?: string;
  /** Optional repository URL to associate with this project in backend */
  repositoryUrl?: string;
  /** Optional source platform label (e.g., gitlab, github, bitbucket) */
  platform?: CiProvider;
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

/** Output of the pure `generateSpdxSbom()` function */
export interface GenerateSpdxSbomResult {
  /** The SPDX document as a parsed JavaScript object */
  sbom: Record<string, unknown>;
  /** The SPDX document as a formatted JSON string */
  content: string;
  /** Number of dependency components represented in the document */
  componentCount: number;
  /** SPDX spec version used */
  specVersion: string;
  /** ISO timestamp of generation */
  generatedAt: string;
}

/** Output of the pure `generateSwidTag()` function */
export interface GenerateSwidTagResult {
  /** The SWID XML tag */
  tag: string;
  /** Alias of `tag` for consistency with the JSON generators */
  content: string;
  /** Number of components represented in the tag */
  componentCount: number;
  /** SWID spec identifier */
  specVersion: string;
  /** ISO timestamp of generation */
  generatedAt: string;
}

// ─── Multi-Project / Recursive Discovery ────────────────────────

/** Represents a discovered lockfile and its associated project */
export interface DiscoveredProject {
  /** Absolute path to the project directory */
  projectPath: string;
  /** Relative path from discovery root (for display/grouping) */
  relativePath: string;
  /** The lockfile that was found */
  lockfile: {
    name: string;
    path: string;
  };
  /** Detected ecosystem */
  ecosystem: Ecosystem;
  /** Scanner that will handle this project */
  scannerType: string;
}

/** Options for recursive discovery */
export interface DiscoveryOptions {
  /** Root path to start discovery from */
  rootPath: string;
  /** Glob patterns to exclude */
  exclude?: string[];
  /** Maximum directory depth to search (default: unlimited) */
  maxDepth?: number;
}

/** Result of multi-project scan */
export interface MultiProjectScanResult {
  /** Total projects discovered */
  totalDiscovered: number;
  /** Projects successfully scanned */
  successful: Array<{
    project: DiscoveredProject;
    report: VerimuReport;
  }>;
  /** Projects that failed to scan */
  failed: Array<{
    project: DiscoveredProject;
    error: string;
  }>;
  /** Projects skipped (e.g., due to filters) */
  skipped: Array<{
    path: string;
    reason: string;
  }>;
  /** Total scan duration */
  durationMs: number;
}

/** Multi-project scan configuration */
export interface MultiProjectConfig extends VerimuConfig {
  /** Enable recursive discovery */
  recursive?: boolean;
  /** Exclude patterns */
  exclude?: string[];
}
