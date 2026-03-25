import type { Ecosystem } from '../../core/types.js';
import type {
  AnalyzerRunContext,
  AnalyzerRunResult,
  UsageContextAnalyzer,
} from './analyzer.interface.js';
import {
  addCandidate,
  collectSourceFiles,
  errorResultFromMessage,
  initState,
  packageKey,
  readSourceFile,
  toAnalyzerResult,
  uniqueTokens,
} from './shared.js';

const RUST_EXTENSIONS = new Set(['.rs']);

interface RustPackagePattern {
  key: string;
  crateNames: string[];
}

export class RustAstAnalyzer implements UsageContextAnalyzer {
  readonly name = 'rust-ast-analyzer';
  private readonly ecosystems = new Set<Ecosystem>(['cargo']);

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
      files = await collectSourceFiles(context.projectPath, RUST_EXTENSIONS);
    } catch (err: unknown) {
      return errorResultFromMessage(
        context,
        this.name,
        err instanceof Error ? err.message : String(err),
        'Failed to enumerate Rust source files',
      );
    }

    for (const filePath of files) {
      if (state.snippetsProduced >= context.maxSnippetsTotal) break;
      const sourceText = await readSourceFile(this.name, context.ecosystem, filePath, state.errors);
      if (sourceText === null) continue;

      const lines = sourceText.split(/\r?\n/);
      const symbolToPackage = new Map<string, string>();

      for (let idx = 0; idx < lines.length; idx++) {
        const line = stripLineComment(lines[idx]).trim();
        const lineNumber = idx + 1;
        if (!line) continue;

        const useMatch = line.match(/^use\s+([A-Za-z_][A-Za-z0-9_:]*)(?:\s+as\s+([A-Za-z_][A-Za-z0-9_]*))?\s*;/);
        if (useMatch) {
          const pathExpr = useMatch[1];
          const alias = useMatch[2] ?? pathExpr.split('::').at(0) ?? pathExpr;
          const crate = pathExpr.split('::').at(0) ?? pathExpr;

          for (const pkg of packagePatterns) {
            if (!pkg.crateNames.includes(crate)) continue;
            symbolToPackage.set(alias, pkg.key);
            symbolToPackage.set(crate, pkg.key);
            addCandidate(context, state, filePath, sourceText, {
              packageKey: pkg.key,
              line: lineNumber,
              matchKind: 'import',
              confidence: 0.94,
            });
          }
          continue;
        }

        const externMatch = line.match(/^extern\s+crate\s+([A-Za-z_][A-Za-z0-9_]*)(?:\s+as\s+([A-Za-z_][A-Za-z0-9_]*))?\s*;/);
        if (externMatch) {
          const crate = externMatch[1];
          const alias = externMatch[2] ?? crate;
          for (const pkg of packagePatterns) {
            if (!pkg.crateNames.includes(crate)) continue;
            symbolToPackage.set(alias, pkg.key);
            symbolToPackage.set(crate, pkg.key);
            addCandidate(context, state, filePath, sourceText, {
              packageKey: pkg.key,
              line: lineNumber,
              matchKind: 'import',
              confidence: 0.94,
            });
          }
          continue;
        }

        const scopedCall = line.match(/\b([A-Za-z_][A-Za-z0-9_]*)::([A-Za-z_][A-Za-z0-9_]*)\s*\(/);
        if (scopedCall) {
          const lhs = scopedCall[1];
          const func = scopedCall[2];
          const pkgKey = symbolToPackage.get(lhs);
          if (pkgKey) {
            addCandidate(context, state, filePath, sourceText, {
              packageKey: pkgKey,
              line: lineNumber,
              matchKind: 'call',
              calledSymbol: `${lhs}::${func}`,
              confidence: 0.8,
            });
          }
        }

        const methodCall = line.match(/\b([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(/);
        if (methodCall) {
          const lhs = methodCall[1];
          const method = methodCall[2];
          const pkgKey = symbolToPackage.get(lhs);
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

  private patternForPackage(packageName: string, ecosystem: Ecosystem): RustPackagePattern {
    const crateName = packageName.replace(/-/g, '_');
    return {
      key: packageKey(ecosystem, packageName),
      crateNames: uniqueTokens([crateName, packageName]),
    };
  }
}

function stripLineComment(line: string): string {
  const idx = line.indexOf("//");
  return idx === -1 ? line : line.slice(0, idx);
}

