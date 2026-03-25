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

const PYTHON_EXTENSIONS = new Set(['.py']);

interface PythonPackagePattern {
  key: string;
  modules: string[];
}

export class PythonAstAnalyzer implements UsageContextAnalyzer {
  readonly name = 'python-ast-analyzer';
  private readonly ecosystems = new Set<Ecosystem>(['pip', 'poetry', 'uv']);

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
      files = await collectSourceFiles(context.projectPath, PYTHON_EXTENSIONS);
    } catch (err: unknown) {
      return errorResultFromMessage(
        context,
        this.name,
        err instanceof Error ? err.message : String(err),
        'Failed to enumerate Python source files',
      );
    }

    for (const filePath of files) {
      if (state.snippetsProduced >= context.maxSnippetsTotal) break;
      const sourceText = await readSourceFile(this.name, context.ecosystem, filePath, state.errors);
      if (sourceText === null) continue;

      const aliasToPackage = new Map<string, string>();
      const lines = sourceText.split(/\r?\n/);

      for (let idx = 0; idx < lines.length; idx++) {
        const line = lines[idx];
        const trimmed = stripInlineComment(line).trim();
        const lineNumber = idx + 1;
        if (!trimmed) continue;

        const importMatch = trimmed.match(/^import\s+(.+)$/);
        if (importMatch) {
          const segments = importMatch[1].split(',').map((part) => part.trim()).filter(Boolean);

          for (const segment of segments) {
            const parsed = segment.match(/^([A-Za-z_][A-Za-z0-9_\.]*)(?:\s+as\s+([A-Za-z_][A-Za-z0-9_]*))?$/);
            if (!parsed) continue;
            const moduleName = parsed[1];
            const alias = parsed[2] ?? moduleName.split('.').at(0) ?? moduleName;
            this.addImportForModule(
              context,
              state,
              filePath,
              sourceText,
              packagePatterns,
              aliasToPackage,
              moduleName,
              alias,
              lineNumber,
            );
          }
          continue;
        }

        const fromMatch = trimmed.match(
          /^from\s+([A-Za-z_][A-Za-z0-9_\.]*)\s+import\s+(.+)$/,
        );
        if (fromMatch) {
          const moduleName = fromMatch[1];
          const imported = fromMatch[2]
            .split(',')
            .map((part) => part.trim())
            .filter(Boolean);

          for (const part of imported) {
            const parsed = part.match(/^([A-Za-z_][A-Za-z0-9_]*)(?:\s+as\s+([A-Za-z_][A-Za-z0-9_]*))?$/);
            if (!parsed) continue;

            const name = parsed[1];
            const alias = parsed[2] ?? name;
            this.addImportForModule(
              context,
              state,
              filePath,
              sourceText,
              packagePatterns,
              aliasToPackage,
              moduleName,
              alias,
              lineNumber,
            );
          }
          continue;
        }

        for (const [alias, pkgKey] of aliasToPackage.entries()) {
          const escapedAlias = escapeRegex(alias);
          const directCall = new RegExp(`\\b${escapedAlias}\\s*\\(`);
          if (directCall.test(trimmed)) {
            addCandidate(context, state, filePath, sourceText, {
              packageKey: pkgKey,
              line: lineNumber,
              matchKind: 'call',
              calledSymbol: alias,
              confidence: 0.78,
            });
          }

          const memberCall = new RegExp(`\\b${escapedAlias}\\s*\\.\\s*([A-Za-z_][A-Za-z0-9_]*)\\s*\\(`);
          const match = trimmed.match(memberCall);
          if (match) {
            addCandidate(context, state, filePath, sourceText, {
              packageKey: pkgKey,
              line: lineNumber,
              matchKind: 'call',
              calledSymbol: `${alias}.${match[1]}`,
              confidence: 0.8,
            });
          }
        }
      }
    }

    return toAnalyzerResult(state);
  }

  private addImportForModule(
    context: AnalyzerRunContext,
    state: ReturnType<typeof initState>,
    filePath: string,
    sourceText: string,
    packagePatterns: PythonPackagePattern[],
    aliasToPackage: Map<string, string>,
    moduleName: string,
    alias: string,
    lineNumber: number,
  ): void {
    const normalizedModule = moduleName.toLowerCase();
    for (const pkg of packagePatterns) {
      const matched = pkg.modules.some((candidate) =>
        normalizedModule === candidate ||
        normalizedModule.startsWith(`${candidate}.`),
      );
      if (!matched) continue;

      aliasToPackage.set(alias, pkg.key);
      aliasToPackage.set(moduleName.split('.').at(0) ?? moduleName, pkg.key);

      addCandidate(context, state, filePath, sourceText, {
        packageKey: pkg.key,
        line: lineNumber,
        matchKind: 'import',
        confidence: 0.95,
      });
    }
  }

  private patternForPackage(packageName: string, ecosystem: Ecosystem): PythonPackagePattern {
    const normalized = toIdentifierToken(packageName).replace(/_/g, '-');
    const base = toIdentifierToken(basePackageName(packageName));
    const packageModules = [
      normalized.replace(/-/g, '_'),
      base.replace(/-/g, '_'),
      base.replace(/_/g, ''),
    ];

    if (normalized === 'pyyaml' || base === 'pyyaml') {
      packageModules.push('yaml');
    }

    return {
      key: packageKey(ecosystem, packageName),
      modules: uniqueTokens(packageModules.map((v) => v.toLowerCase())),
    };
  }
}

function stripInlineComment(line: string): string {
  const hashIndex = line.indexOf('#');
  return hashIndex === -1 ? line : line.slice(0, hashIndex);
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

