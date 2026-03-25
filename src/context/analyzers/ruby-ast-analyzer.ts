import type { Ecosystem } from '../../core/types.js';
import type {
  AnalyzerRunContext,
  AnalyzerRunResult,
  UsageContextAnalyzer,
} from './analyzer.interface.js';
import {
  addCandidate,
  basePackageName,
  collectSourceFiles,
  errorResultFromMessage,
  initState,
  packageKey,
  readSourceFile,
  toAnalyzerResult,
  uniqueTokens,
} from './shared.js';

const RUBY_EXTENSIONS = new Set(['.rb']);

interface RubyPackagePattern {
  key: string;
  requireCandidates: string[];
  constantCandidates: string[];
}

export class RubyAstAnalyzer implements UsageContextAnalyzer {
  readonly name = 'ruby-ast-analyzer';
  private readonly ecosystems = new Set<Ecosystem>(['ruby']);

  supports(ecosystem: Ecosystem): boolean {
    return this.ecosystems.has(ecosystem);
  }

  async analyze(context: AnalyzerRunContext): Promise<AnalyzerRunResult> {
    const state = initState(context.packages);
    const packagePatterns = context.packages.map((pkg) =>
      this.patternForPackage(pkg.packageName, pkg.ecosystem),
    );

    let files: string[];
    try {
      files = await collectSourceFiles(context.projectPath, RUBY_EXTENSIONS);
    } catch (err: unknown) {
      return errorResultFromMessage(
        context,
        this.name,
        err instanceof Error ? err.message : String(err),
        'Failed to enumerate Ruby source files',
      );
    }

    for (const filePath of files) {
      if (state.snippetsProduced >= context.maxSnippetsTotal) break;
      const sourceText = await readSourceFile(this.name, context.ecosystem, filePath, state.errors);
      if (sourceText === null) continue;

      const lines = sourceText.split(/\r?\n/);
      const symbolToPackage = new Map<string, string>();

      for (let idx = 0; idx < lines.length; idx++) {
        const line = stripInlineComment(lines[idx]).trim();
        const lineNumber = idx + 1;
        if (!line) continue;

        const requireMatch = line.match(/^require(?:_relative)?\s+['"]([^'"]+)['"]/);
        if (requireMatch) {
          const requiredPath = requireMatch[1];
          for (const pkg of packagePatterns) {
            if (!pkg.requireCandidates.some((candidate) => requiredPath.includes(candidate))) continue;
            addCandidate(context, state, filePath, sourceText, {
              packageKey: pkg.key,
              line: lineNumber,
              matchKind: 'require',
              confidence: 0.93,
            });

            for (const constant of pkg.constantCandidates) {
              symbolToPackage.set(constant, pkg.key);
            }
          }
          continue;
        }

        const includeMatch = line.match(/^include\s+([A-Za-z_][A-Za-z0-9_:]*)/);
        if (includeMatch) {
          const moduleName = includeMatch[1];
          for (const pkg of packagePatterns) {
            if (!pkg.constantCandidates.some((candidate) => moduleName.startsWith(candidate))) continue;
            symbolToPackage.set(moduleName.split('::').at(0) ?? moduleName, pkg.key);
            addCandidate(context, state, filePath, sourceText, {
              packageKey: pkg.key,
              line: lineNumber,
              matchKind: 'import',
              confidence: 0.9,
            });
          }
          continue;
        }

        const namespacedCall = line.match(/\b([A-Z][A-Za-z0-9_:]*)\s*(?:\.|::)\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(/);
        if (namespacedCall) {
          const lhs = namespacedCall[1].split('::').at(0) ?? namespacedCall[1];
          const method = namespacedCall[2];
          const pkgKey = symbolToPackage.get(lhs)
            ?? this.findConstantCandidatePackage(lhs, packagePatterns);
          if (pkgKey) {
            addCandidate(context, state, filePath, sourceText, {
              packageKey: pkgKey,
              line: lineNumber,
              matchKind: 'call',
              calledSymbol: `${lhs}.${method}`,
              confidence: 0.78,
            });
          }
        }
      }
    }

    return toAnalyzerResult(state);
  }

  private patternForPackage(packageName: string, ecosystem: Ecosystem): RubyPackagePattern {
    const base = basePackageName(packageName);
    const normalized = base.toLowerCase();
    const requireCandidates = uniqueTokens([
      normalized,
      normalized.replace(/-/g, '/'),
      normalized.replace(/-/g, '_'),
    ]);

    const constantParts = normalized
      .replace(/[^a-z0-9_/-]/g, '')
      .split(/[\/_-]+/)
      .filter(Boolean)
      .map((part) => part[0]?.toUpperCase() + part.slice(1));
    const constant = constantParts.join('::');
    const collapsedConstant = constantParts.join('');

    return {
      key: packageKey(ecosystem, packageName),
      requireCandidates,
      constantCandidates: uniqueTokens([constant, collapsedConstant, constantParts.at(0) ?? '']),
    };
  }

  private findConstantCandidatePackage(
    constant: string,
    packagePatterns: RubyPackagePattern[],
  ): string | null {
    for (const pkg of packagePatterns) {
      if (pkg.constantCandidates.includes(constant)) {
        return pkg.key;
      }
    }
    return null;
  }
}

function stripInlineComment(line: string): string {
  const idx = line.indexOf('#');
  return idx === -1 ? line : line.slice(0, idx);
}
