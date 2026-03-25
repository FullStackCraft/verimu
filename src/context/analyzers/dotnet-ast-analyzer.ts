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

const CSHARP_EXTENSIONS = new Set(['.cs']);

interface DotnetPackagePattern {
  key: string;
  namespaceCandidates: string[];
  symbolCandidates: string[];
}

export class DotnetAstAnalyzer implements UsageContextAnalyzer {
  readonly name = 'dotnet-ast-analyzer';
  private readonly ecosystems = new Set<Ecosystem>(['nuget']);

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
      files = await collectSourceFiles(context.projectPath, CSHARP_EXTENSIONS);
    } catch (err: unknown) {
      return errorResultFromMessage(
        context,
        this.name,
        err instanceof Error ? err.message : String(err),
        'Failed to enumerate C# source files',
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

        const aliasUsing = line.match(/^using\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z0-9_.]+)\s*;/);
        if (aliasUsing) {
          const alias = aliasUsing[1];
          const targetNamespace = aliasUsing[2];
          for (const pkg of packagePatterns) {
            if (!pkg.namespaceCandidates.some((candidate) => targetNamespace.startsWith(candidate))) continue;

            symbolToPackage.set(alias, pkg.key);
            addCandidate(context, state, filePath, sourceText, {
              packageKey: pkg.key,
              line: lineNumber,
              matchKind: 'import',
              confidence: 0.93,
            });
          }
          continue;
        }

        const usingMatch = line.match(/^using\s+([A-Za-z0-9_.]+)\s*;/);
        if (usingMatch) {
          const namespaceName = usingMatch[1];
          const tailSymbol = namespaceName.split('.').at(-1) ?? namespaceName;
          for (const pkg of packagePatterns) {
            if (!pkg.namespaceCandidates.some((candidate) => namespaceName.startsWith(candidate))) continue;

            symbolToPackage.set(tailSymbol, pkg.key);
            addCandidate(context, state, filePath, sourceText, {
              packageKey: pkg.key,
              line: lineNumber,
              matchKind: 'import',
              confidence: 0.93,
            });
          }
          continue;
        }

        // Capture type declarations assigned to variables.
        const varDecl = line.match(/^([A-Za-z_][A-Za-z0-9_.]*)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:=|;)/);
        if (varDecl) {
          const typeName = varDecl[1].split('.').at(-1) ?? varDecl[1];
          const variableName = varDecl[2];
          const pkgKey = symbolToPackage.get(typeName);
          if (pkgKey) {
            symbolToPackage.set(variableName, pkgKey);
          }
        }

        const memberCall = line.match(/\b([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(/);
        if (memberCall) {
          const lhs = memberCall[1];
          const method = memberCall[2];
          const pkgKey = symbolToPackage.get(lhs)
            ?? this.findSymbolCandidatePackage(lhs, packagePatterns);
          if (pkgKey) {
            addCandidate(context, state, filePath, sourceText, {
              packageKey: pkgKey,
              line: lineNumber,
              matchKind: 'call',
              calledSymbol: `${lhs}.${method}`,
              confidence: 0.79,
            });
          }
        }
      }
    }

    return toAnalyzerResult(state);
  }

  private patternForPackage(packageName: string, ecosystem: Ecosystem): DotnetPackagePattern {
    const dotted = packageName.replace(/-/g, '.');
    const segments = dotted.split('.');
    const symbolCandidates = uniqueTokens([
      segments.at(-1) ?? '',
      segments.at(-2) ?? '',
      packageName.split('.').at(-1) ?? '',
    ]);

    const namespaceCandidates = uniqueTokens([
      dotted,
      segments.slice(0, -1).join('.'),
      segments.slice(0, Math.min(2, segments.length)).join('.'),
    ]);

    return {
      key: packageKey(ecosystem, packageName),
      namespaceCandidates,
      symbolCandidates,
    };
  }

  private findSymbolCandidatePackage(
    symbol: string,
    packagePatterns: DotnetPackagePattern[],
  ): string | null {
    for (const pkg of packagePatterns) {
      if (pkg.symbolCandidates.includes(symbol)) {
        return pkg.key;
      }
    }
    return null;
  }
}

function stripLineComment(line: string): string {
  const idx = line.indexOf('//');
  return idx === -1 ? line : line.slice(0, idx);
}

