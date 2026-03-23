import type {
  Dependency,
  Ecosystem,
  UsageContextEcosystemStatus,
  UsageContextError,
  UsageContextLlmPayload,
  UsageContextResult,
  UsageContextVulnerabilityFinding,
  Vulnerability,
} from '../core/types.js';
import { normalizeNumContextLines } from './snippet-extractor.js';
import type {
  AnalyzerRunContext,
  PackageAnalysisResult,
  UsageContextAnalyzer,
  VulnerablePackageInput,
} from './analyzers/analyzer.interface.js';
import { JsAstAnalyzer } from './analyzers/js-ast-analyzer.js';
import { UnsupportedAnalyzer } from './analyzers/unsupported-analyzer.js';

const DEFAULT_MAX_SNIPPETS_PER_PACKAGE = 20;
const DEFAULT_MAX_SNIPPETS_TOTAL = 500;

export interface UsageContextEngineInput {
  projectPath: string;
  dependencies: Dependency[];
  vulnerabilities: Vulnerability[];
  numContextLines?: number;
  maxSnippetsPerPackage?: number;
  maxSnippetsTotal?: number;
}

export class UsageContextEngine {
  private readonly analyzers: UsageContextAnalyzer[];

  constructor(analyzers?: UsageContextAnalyzer[]) {
    this.analyzers = analyzers ?? [
      new JsAstAnalyzer(),
      new UnsupportedAnalyzer(
        'python-ast-analyzer',
        ['pip', 'poetry', 'uv'],
        'Python AST analyzer is not yet implemented in this release',
      ),
      new UnsupportedAnalyzer(
        'java-ast-analyzer',
        ['maven'],
        'Java AST analyzer is not yet implemented in this release',
      ),
      new UnsupportedAnalyzer(
        'dotnet-ast-analyzer',
        ['nuget'],
        'NuGet/C# AST analyzer is not yet implemented in this release',
      ),
      new UnsupportedAnalyzer(
        'rust-ast-analyzer',
        ['cargo'],
        'Rust AST analyzer is not yet implemented in this release',
      ),
      new UnsupportedAnalyzer(
        'go-ast-analyzer',
        ['go'],
        'Go AST analyzer is not yet implemented in this release',
      ),
      new UnsupportedAnalyzer(
        'ruby-ast-analyzer',
        ['ruby'],
        'Ruby AST analyzer is not yet implemented in this release',
      ),
      new UnsupportedAnalyzer(
        'php-ast-analyzer',
        ['composer'],
        'PHP AST analyzer is not yet implemented in this release',
      ),
    ];
  }

  async analyze(input: UsageContextEngineInput): Promise<UsageContextResult> {
    const startTime = Date.now();
    const numContextLines = normalizeNumContextLines(input.numContextLines);
    const maxSnippetsPerPackage = this.normalizePositiveInt(
      input.maxSnippetsPerPackage,
      DEFAULT_MAX_SNIPPETS_PER_PACKAGE,
    );
    const maxSnippetsTotal = this.normalizePositiveInt(
      input.maxSnippetsTotal,
      DEFAULT_MAX_SNIPPETS_TOTAL,
    );

    const packageInputs = this.buildVulnerablePackages(input.vulnerabilities, input.dependencies);
    const findings: UsageContextVulnerabilityFinding[] = [];
    const llmPayload: UsageContextLlmPayload[] = [];
    const ecosystemStatus: UsageContextEcosystemStatus[] = [];
    const errors: UsageContextError[] = [];

    let remainingSnippets = maxSnippetsTotal;

    for (const [ecosystem, packages] of groupByEcosystem(packageInputs)) {
      const analyzer = this.pickAnalyzer(ecosystem);
      if (!analyzer) {
        const note = `No analyzer configured for ecosystem ${ecosystem}`;
        ecosystemStatus.push({
          ecosystem,
          analyzer: 'none',
          status: 'error',
          vulnerablePackages: packages.length,
          snippetsFound: 0,
          note,
        });

        errors.push({ analyzer: 'none', ecosystem, error: note });

        for (const pkg of packages) {
          this.addFindingsForPackage({
            packageInput: pkg,
            packageResult: {
              packageName: pkg.packageName,
              ecosystem: pkg.ecosystem,
              status: 'analysis_error',
              snippets: [],
              notes: note,
            },
            findings,
            llmPayload,
          });
        }
        continue;
      }

      const runContext: AnalyzerRunContext = {
        projectPath: input.projectPath,
        ecosystem,
        packages,
        numContextLines,
        maxSnippetsPerPackage,
        maxSnippetsTotal: remainingSnippets,
      };

      try {
        const result = await analyzer.analyze(runContext);
        const resultByKey = new Map(
          result.packages.map((pkg) => [packageKey(pkg.ecosystem, pkg.packageName), pkg]),
        );

        errors.push(...result.errors);
        remainingSnippets = Math.max(0, remainingSnippets - result.snippetsProduced);

        let snippetsFound = 0;
        let unsupportedCount = 0;
        let analysisErrorCount = 0;

        for (const pkg of packages) {
          const analyzed = resultByKey.get(packageKey(pkg.ecosystem, pkg.packageName)) ?? {
            packageName: pkg.packageName,
            ecosystem: pkg.ecosystem,
            status: 'analysis_error',
            snippets: [],
            notes: 'Analyzer returned no package result',
          };

          if (analyzed.status === 'unsupported') unsupportedCount += 1;
          if (analyzed.status === 'analysis_error') analysisErrorCount += 1;
          snippetsFound += analyzed.snippets.length;

          this.addFindingsForPackage({
            packageInput: pkg,
            packageResult: analyzed,
            findings,
            llmPayload,
          });
        }

        ecosystemStatus.push({
          ecosystem,
          analyzer: analyzer.name,
          status:
            analysisErrorCount === packages.length
              ? 'error'
              : unsupportedCount === packages.length
                ? 'unsupported'
                : 'analyzed',
          vulnerablePackages: packages.length,
          snippetsFound,
          note: result.errors.length > 0 ? `${result.errors.length} non-fatal analyzer errors` : undefined,
        });
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);

        errors.push({ analyzer: analyzer.name, ecosystem, error: message });
        ecosystemStatus.push({
          ecosystem,
          analyzer: analyzer.name,
          status: 'error',
          vulnerablePackages: packages.length,
          snippetsFound: 0,
          note: message,
        });

        for (const pkg of packages) {
          this.addFindingsForPackage({
            packageInput: pkg,
            packageResult: {
              packageName: pkg.packageName,
              ecosystem: pkg.ecosystem,
              status: 'analysis_error',
              snippets: [],
              notes: 'Analyzer execution failed',
            },
            findings,
            llmPayload,
          });
        }
      }
    }

    const totalSnippets = findings.reduce((sum, finding) => sum + finding.evidenceCount, 0);

    return {
      triggered: true,
      durationMs: Date.now() - startTime,
      numContextLines,
      maxSnippetsPerPackage,
      maxSnippetsTotal,
      totalSnippets,
      packageFindings: findings,
      ecosystemStatus,
      errors,
      llmPayload,
    };
  }

  private addFindingsForPackage(params: {
    packageInput: VulnerablePackageInput;
    packageResult: PackageAnalysisResult;
    findings: UsageContextVulnerabilityFinding[];
    llmPayload: UsageContextLlmPayload[];
  }): void {
    const { packageInput, packageResult, findings, llmPayload } = params;

    for (const vulnerability of packageInput.vulnerabilities) {
      const finding: UsageContextVulnerabilityFinding = {
        vulnerabilityId: vulnerability.id,
        packageName: packageInput.packageName,
        ecosystem: packageInput.ecosystem,
        directDependency: packageInput.directDependency,
        status: packageResult.status,
        snippets: packageResult.snippets,
        evidenceCount: packageResult.snippets.length,
        notes: packageResult.notes,
      };

      findings.push(finding);
      llmPayload.push({
        vulnerability: {
          id: vulnerability.id,
          aliases: vulnerability.aliases,
          severity: vulnerability.severity,
          summary: vulnerability.summary,
          affectedVersionRange: vulnerability.affectedVersionRange,
          fixedVersion: vulnerability.fixedVersion,
          referenceUrl: vulnerability.referenceUrl,
        },
        package: {
          name: packageInput.packageName,
          ecosystem: packageInput.ecosystem,
          directDependency: packageInput.directDependency,
        },
        status: finding.status,
        evidenceCount: finding.evidenceCount,
        snippets: finding.snippets,
        notes: finding.notes,
      });
    }
  }

  private buildVulnerablePackages(
    vulnerabilities: Vulnerability[],
    dependencies: Dependency[],
  ): VulnerablePackageInput[] {
    const directMap = new Map<string, boolean>();

    for (const dependency of dependencies) {
      const key = packageKey(dependency.ecosystem, dependency.name);
      const existing = directMap.get(key) ?? false;
      directMap.set(key, existing || dependency.direct);
    }

    const grouped = new Map<string, VulnerablePackageInput>();

    for (const vulnerability of vulnerabilities) {
      const key = packageKey(vulnerability.ecosystem, vulnerability.packageName);
      const existing = grouped.get(key);

      if (existing) {
        existing.vulnerabilities.push(vulnerability);
      } else {
        grouped.set(key, {
          packageName: vulnerability.packageName,
          ecosystem: vulnerability.ecosystem,
          directDependency: directMap.has(key) ? directMap.get(key) ?? false : null,
          vulnerabilities: [vulnerability],
        });
      }
    }

    return Array.from(grouped.values());
  }

  private pickAnalyzer(ecosystem: Ecosystem): UsageContextAnalyzer | null {
    return this.analyzers.find((analyzer) => analyzer.supports(ecosystem)) ?? null;
  }

  private normalizePositiveInt(value: number | undefined, fallback: number): number {
    if (!Number.isFinite(value)) return fallback;
    const n = Math.floor(value as number);
    return n > 0 ? n : fallback;
  }
}

function packageKey(ecosystem: Ecosystem, packageName: string): string {
  return `${ecosystem}::${packageName}`;
}

function groupByEcosystem(
  packages: VulnerablePackageInput[],
): Array<[Ecosystem, VulnerablePackageInput[]]> {
  const grouped = new Map<Ecosystem, VulnerablePackageInput[]>();

  for (const pkg of packages) {
    const existing = grouped.get(pkg.ecosystem) ?? [];
    existing.push(pkg);
    grouped.set(pkg.ecosystem, existing);
  }

  return Array.from(grouped.entries());
}
