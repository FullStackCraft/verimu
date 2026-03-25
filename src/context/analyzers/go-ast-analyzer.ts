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
  toIdentifierToken,
  uniqueTokens,
} from './shared.js';

const GO_EXTENSIONS = new Set(['.go']);

interface GoPackagePattern {
  key: string;
  packageName: string;
  aliases: string[];
}

export class GoAstAnalyzer implements UsageContextAnalyzer {
  readonly name = 'go-ast-analyzer';
  private readonly ecosystems = new Set<Ecosystem>(['go']);

  supports(ecosystem: Ecosystem): boolean {
    return this.ecosystems.has(ecosystem);
  }

  async analyze(context: AnalyzerRunContext): Promise<AnalyzerRunResult> {
    const state = initState(context.packages);
    const packagePatterns = context.packages.map((pkg) => this.patternForPackage(pkg.packageName, pkg.ecosystem));

    let files: string[];
    try {
      files = await collectSourceFiles(context.projectPath, GO_EXTENSIONS);
    } catch (err: unknown) {
      return errorResultFromMessage(
        context,
        this.name,
        err instanceof Error ? err.message : String(err),
        'Failed to enumerate Go source files',
      );
    }

    for (const filePath of files) {
      if (state.snippetsProduced >= context.maxSnippetsTotal) break;
      const sourceText = await readSourceFile(this.name, context.ecosystem, filePath, state.errors);
      if (sourceText === null) continue;

      const aliasesByPackage = new Map<string, Set<string>>();
      for (const pkg of packagePatterns) {
        aliasesByPackage.set(pkg.key, new Set(pkg.aliases));
      }

      const lines = sourceText.split(/\r?\n/);
      let inImportBlock = false;

      for (let idx = 0; idx < lines.length; idx++) {
        const lineNumber = idx + 1;
        const line = lines[idx];
        const trimmed = line.trim();

        if (trimmed.startsWith('import (')) {
          inImportBlock = true;
          continue;
        }

        if (inImportBlock && trimmed === ')') {
          inImportBlock = false;
          continue;
        }

        const match = this.extractImport(trimmed, inImportBlock);
        if (match) {
          for (const pkg of packagePatterns) {
            if (match.importPath !== pkg.packageName) continue;

            const alias = match.alias && match.alias !== '_' && match.alias !== '.'
              ? toIdentifierToken(match.alias)
              : pkg.aliases[0];

            if (alias) {
              aliasesByPackage.get(pkg.key)?.add(alias);
            }

            addCandidate(context, state, filePath, sourceText, {
              packageKey: pkg.key,
              line: lineNumber,
              matchKind: 'import',
              confidence: 0.95,
            });
          }
        }

        for (const pkg of packagePatterns) {
          const aliases = aliasesByPackage.get(pkg.key);
          if (!aliases) continue;

          for (const alias of aliases) {
            if (!alias) continue;

            const escapedAlias = escapeRegex(alias);
            const callRegex = new RegExp(`\\b${escapedAlias}\\s*\\.\\s*([A-Za-z_][A-Za-z0-9_]*)\\s*\\(`);
            const callMatch = line.match(callRegex);
            if (!callMatch) continue;

            addCandidate(context, state, filePath, sourceText, {
              packageKey: pkg.key,
              line: lineNumber,
              matchKind: 'call',
              calledSymbol: `${alias}.${callMatch[1]}`,
              confidence: 0.8,
            });
          }
        }
      }
    }

    return toAnalyzerResult(state);
  }

  private patternForPackage(packageName: string, ecosystem: Ecosystem): GoPackagePattern {
    const baseName = basePackageName(packageName);
    const identifierBase = toIdentifierToken(baseName.replace(/^v[0-9]+$/, ''));
    const shortened = identifierBase.replace(/go$/i, '') || identifierBase;

    return {
      key: packageKey(ecosystem, packageName),
      packageName,
      aliases: uniqueTokens([identifierBase, shortened]),
    };
  }

  private extractImport(
    trimmedLine: string,
    inImportBlock: boolean,
  ): { alias: string | null; importPath: string } | null {
    if (!inImportBlock && !trimmedLine.startsWith('import ')) return null;

    if (inImportBlock) {
      const blockMatch = trimmedLine.match(/^(?:(\.|_|[A-Za-z_][A-Za-z0-9_]*)\s+)?\"([^\"]+)\"/);
      if (!blockMatch) return null;
      return {
        alias: blockMatch[1] ?? null,
        importPath: blockMatch[2],
      };
    }

    const singleMatch = trimmedLine.match(/^import\s+(?:(\.|_|[A-Za-z_][A-Za-z0-9_]*)\s+)?\"([^\"]+)\"/);
    if (!singleMatch) return null;
    return {
      alias: singleMatch[1] ?? null,
      importPath: singleMatch[2],
    };
  }
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

