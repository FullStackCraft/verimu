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
  toIdentifierToken,
  uniqueTokens,
} from './shared.js';

const JAVA_EXTENSIONS = new Set(['.java']);

interface JavaPackagePattern {
  key: string;
  candidates: string[];
}

export class JavaAstAnalyzer implements UsageContextAnalyzer {
  readonly name = 'java-ast-analyzer';
  private readonly ecosystems = new Set<Ecosystem>(['maven']);

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
      files = await collectSourceFiles(context.projectPath, JAVA_EXTENSIONS);
    } catch (err: unknown) {
      return errorResultFromMessage(
        context,
        this.name,
        err instanceof Error ? err.message : String(err),
        'Failed to enumerate Java source files',
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

        const importMatch = line.match(/^import\s+(?:static\s+)?([A-Za-z0-9_.*]+)\s*;/);
        if (importMatch) {
          const importPath = importMatch[1].replace(/\.\*$/, '');
          const simpleName = importPath.split('.').at(-1) ?? importPath;

          for (const pkg of packagePatterns) {
            if (!pkg.candidates.some((candidate) => importPath.startsWith(candidate))) continue;

            addCandidate(context, state, filePath, sourceText, {
              packageKey: pkg.key,
              line: lineNumber,
              matchKind: 'import',
              confidence: 0.94,
            });

            if (simpleName && /^[A-Za-z_][A-Za-z0-9_]*$/.test(simpleName)) {
              symbolToPackage.set(simpleName, pkg.key);
            }
          }
          continue;
        }

        // Track variable names that are instances of imported classes.
        const varDecl = line.match(/^([A-Za-z_][A-Za-z0-9_]*)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:=|;)/);
        if (varDecl) {
          const typeName = varDecl[1];
          const variableName = varDecl[2];
          const pkgKey = symbolToPackage.get(typeName);
          if (pkgKey) {
            symbolToPackage.set(variableName, pkgKey);
          }
        }

        const callMatch = line.match(/\b([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(/);
        if (!callMatch) continue;

        const lhs = callMatch[1];
        const member = callMatch[2];
        const pkgKey = symbolToPackage.get(lhs);
        if (!pkgKey) continue;

        addCandidate(context, state, filePath, sourceText, {
          packageKey: pkgKey,
          line: lineNumber,
          matchKind: 'call',
          calledSymbol: `${lhs}.${member}`,
          confidence: 0.8,
        });
      }
    }

    return toAnalyzerResult(state);
  }

  private patternForPackage(packageName: string, ecosystem: Ecosystem): JavaPackagePattern {
    const [groupIdRaw, artifactIdRaw] = packageName.split(':');
    const groupId = (groupIdRaw ?? '').trim();
    const artifactId = (artifactIdRaw ?? '').trim();

    const candidates = uniqueTokens([
      groupId,
      groupId && artifactId ? `${groupId}.${artifactId.replace(/-/g, '.')}` : '',
      artifactId ? artifactId.replace(/-/g, '.') : '',
      artifactId ? toIdentifierToken(artifactId).replace(/_/g, '.') : '',
    ]);

    return {
      key: packageKey(ecosystem, packageName),
      candidates,
    };
  }
}

function stripLineComment(line: string): string {
  const idx = line.indexOf('//');
  return idx === -1 ? line : line.slice(0, idx);
}

