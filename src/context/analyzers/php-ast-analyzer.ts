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

const PHP_EXTENSIONS = new Set(['.php']);

interface PhpPackagePattern {
  key: string;
  vendor: string;
  package: string;
  namespaceCandidates: string[];
  symbolCandidates: string[];
}

export class PhpAstAnalyzer implements UsageContextAnalyzer {
  readonly name = 'php-ast-analyzer';
  private readonly ecosystems = new Set<Ecosystem>(['composer']);

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
      files = await collectSourceFiles(context.projectPath, PHP_EXTENSIONS);
    } catch (err: unknown) {
      return errorResultFromMessage(
        context,
        this.name,
        err instanceof Error ? err.message : String(err),
        'Failed to enumerate PHP source files',
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

        const useMatch = line.match(/^use\s+([A-Za-z0-9_\\]+)(?:\s+as\s+([A-Za-z_][A-Za-z0-9_]*))?\s*;/i);
        if (useMatch) {
          const namespacePath = useMatch[1];
          const alias = useMatch[2] ?? namespacePath.split('\\').at(-1) ?? namespacePath;

          for (const pkg of packagePatterns) {
            const normalizedNamespace = namespacePath.toLowerCase();
            if (!pkg.namespaceCandidates.some((candidate) => normalizedNamespace.startsWith(candidate.toLowerCase()))) continue;
            symbolToPackage.set(alias, pkg.key);

            addCandidate(context, state, filePath, sourceText, {
              packageKey: pkg.key,
              line: lineNumber,
              matchKind: 'import',
              confidence: 0.94,
            });
          }
          continue;
        }

        const requireMatch = line.match(/^require(?:_once)?\s*\(?\s*['"]([^'"]+)['"]\s*\)?\s*;/i);
        if (requireMatch) {
          const pathExpr = requireMatch[1].toLowerCase();
          for (const pkg of packagePatterns) {
            const hasVendor = pathExpr.includes(pkg.vendor.toLowerCase());
            const hasPackage = pathExpr.includes(pkg.package.toLowerCase());
            if (!hasVendor && !hasPackage) continue;

            addCandidate(context, state, filePath, sourceText, {
              packageKey: pkg.key,
              line: lineNumber,
              matchKind: 'require',
              confidence: 0.9,
            });
          }
          continue;
        }

        const staticCall = line.match(/\b([A-Za-z_][A-Za-z0-9_]*)::([A-Za-z_][A-Za-z0-9_]*)\s*\(/);
        if (staticCall) {
          const lhs = staticCall[1];
          const method = staticCall[2];
          const pkgKey = symbolToPackage.get(lhs)
            ?? this.findSymbolCandidatePackage(lhs, packagePatterns);
          if (pkgKey) {
            addCandidate(context, state, filePath, sourceText, {
              packageKey: pkgKey,
              line: lineNumber,
              matchKind: 'call',
              calledSymbol: `${lhs}::${method}`,
              confidence: 0.8,
            });
          }
        }

        const constructorMatch = line.match(/new\s+([A-Za-z_][A-Za-z0-9_]*)\b/);
        if (constructorMatch) {
          const className = constructorMatch[1];
          const pkgKey = symbolToPackage.get(className)
            ?? this.findSymbolCandidatePackage(className, packagePatterns);
          if (pkgKey) {
            addCandidate(context, state, filePath, sourceText, {
              packageKey: pkgKey,
              line: lineNumber,
              matchKind: 'call',
              calledSymbol: `new ${className}`,
              confidence: 0.76,
            });
          }
        }
      }
    }

    return toAnalyzerResult(state);
  }

  private patternForPackage(packageName: string, ecosystem: Ecosystem): PhpPackagePattern {
    const [vendorRaw, packageRaw] = packageName.split('/');
    const vendor = vendorRaw ?? packageName;
    const packagePart = packageRaw ?? packageName;

    const namespaceCandidates = uniqueTokens([
      pascalize(vendor),
      pascalize(packagePart),
      `${pascalize(vendor)}\\${pascalize(packagePart)}`,
      `${pascalize(vendor)}\\${pascalize(packagePart.replace(/-/g, '_'))}`,
    ]);

    const symbolCandidates = uniqueTokens([
      pascalize(packagePart),
      pascalize(vendor),
      pascalize(packagePart).split('\\').at(-1) ?? '',
    ]);

    return {
      key: packageKey(ecosystem, packageName),
      vendor,
      package: packagePart,
      namespaceCandidates,
      symbolCandidates,
    };
  }

  private findSymbolCandidatePackage(
    symbol: string,
    packagePatterns: PhpPackagePattern[],
  ): string | null {
    const normalized = symbol.toLowerCase();
    for (const pkg of packagePatterns) {
      if (pkg.symbolCandidates.some((candidate) => candidate.toLowerCase() === normalized)) {
        return pkg.key;
      }
    }
    return null;
  }
}

function pascalize(input: string): string {
  return input
    .split(/[\/_.-]+/)
    .filter(Boolean)
    .map((part) => part[0]?.toUpperCase() + part.slice(1))
    .join('\\');
}

function stripLineComment(line: string): string {
  const slashIdx = line.indexOf('//');
  if (slashIdx !== -1) return line.slice(0, slashIdx);
  const hashIdx = line.indexOf('#');
  return hashIdx === -1 ? line : line.slice(0, hashIdx);
}
