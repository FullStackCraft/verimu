import type {
  AnalyzerRunContext,
  AnalyzerRunResult,
  PackageAnalysisResult,
  UsageContextAnalyzer,
} from './analyzer.interface.js';
import type { Ecosystem } from '../../core/types.js';

export class UnsupportedAnalyzer implements UsageContextAnalyzer {
  readonly name: string;
  private readonly ecosystems: Set<Ecosystem>;
  private readonly note: string;

  constructor(name: string, ecosystems: Ecosystem[], note: string) {
    this.name = name;
    this.ecosystems = new Set(ecosystems);
    this.note = note;
  }

  supports(ecosystem: Ecosystem): boolean {
    return this.ecosystems.has(ecosystem);
  }

  async analyze(context: AnalyzerRunContext): Promise<AnalyzerRunResult> {
    const packages: PackageAnalysisResult[] = context.packages.map((pkg) => ({
      packageName: pkg.packageName,
      ecosystem: pkg.ecosystem,
      status: 'unsupported',
      snippets: [],
      notes: this.note,
    }));

    return {
      packages,
      errors: [],
      snippetsProduced: 0,
    };
  }
}
