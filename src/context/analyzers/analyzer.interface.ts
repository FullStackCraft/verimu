import type {
  Ecosystem,
  UsageContextError,
  UsageContextStatus,
  UsageSnippet,
  Vulnerability,
} from '../../core/types.js';

export interface VulnerablePackageInput {
  packageName: string;
  ecosystem: Ecosystem;
  directDependency: boolean | null;
  vulnerabilities: Vulnerability[];
}

export interface PackageAnalysisResult {
  packageName: string;
  ecosystem: Ecosystem;
  status: UsageContextStatus;
  snippets: UsageSnippet[];
  notes?: string;
}

export interface AnalyzerRunContext {
  projectPath: string;
  ecosystem: Ecosystem;
  packages: VulnerablePackageInput[];
  numContextLines: number;
  maxSnippetsPerPackage: number;
  maxSnippetsTotal: number;
}

export interface AnalyzerRunResult {
  packages: PackageAnalysisResult[];
  errors: UsageContextError[];
  snippetsProduced: number;
}

export interface UsageContextAnalyzer {
  readonly name: string;
  supports(ecosystem: Ecosystem): boolean;
  analyze(context: AnalyzerRunContext): Promise<AnalyzerRunResult>;
}
