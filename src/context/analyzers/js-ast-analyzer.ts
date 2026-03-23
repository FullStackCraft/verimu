import { readdir, readFile } from 'fs/promises';
import { join } from 'path';
import { parse } from '@babel/parser';
import traverse from '@babel/traverse';
import {
  isIdentifier,
  isImportSpecifier,
  isImportDefaultSpecifier,
  isImportNamespaceSpecifier,
  isStringLiteral,
  isCallExpression,
  isImport,
  isMemberExpression,
  isOptionalMemberExpression,
  isVariableDeclarator,
  isObjectPattern,
  isArrayPattern,
  isRestElement,
  isAssignmentPattern,
  isTSAsExpression,
  isTSSatisfiesExpression,
  isTSTypeAssertion,
  isParenthesizedExpression,
} from '@babel/types';
import type {
  Expression,
  OptionalMemberExpression,
} from '@babel/types';
import type { Ecosystem, UsageContextError, UsageSnippetMatchKind } from '../../core/types.js';
import { buildSnippet, dedupeSnippets } from '../snippet-extractor.js';
import type {
  AnalyzerRunContext,
  AnalyzerRunResult,
  PackageAnalysisResult,
  UsageContextAnalyzer,
  VulnerablePackageInput,
} from './analyzer.interface.js';

const JS_EXTENSIONS = new Set([
  '.js',
  '.jsx',
  '.mjs',
  '.cjs',
  '.ts',
  '.tsx',
  '.mts',
  '.cts',
]);

const IGNORED_DIRS = new Set([
  '.git',
  '.hg',
  '.svn',
  'node_modules',
  'dist',
  'build',
  'coverage',
  '.next',
  '.nuxt',
  '.turbo',
]);

interface ImportTarget {
  packageName: string;
  ecosystemHint: Ecosystem | null;
}

interface MatchCandidate {
  packageKey: string;
  line: number;
  matchKind: UsageSnippetMatchKind;
  calledSymbol?: string;
  confidence: number;
}

export class JsAstAnalyzer implements UsageContextAnalyzer {
  readonly name = 'js-ast-analyzer';
  private readonly ecosystems = new Set<Ecosystem>(['npm', 'deno']);

  supports(ecosystem: Ecosystem): boolean {
    return this.ecosystems.has(ecosystem);
  }

  async analyze(context: AnalyzerRunContext): Promise<AnalyzerRunResult> {
    const packageMap = this.buildPackageMaps(context.packages);
    const resultMap = new Map<string, PackageAnalysisResult>();
    const snippetKeyMap = new Map<string, Set<string>>();
    const errors: UsageContextError[] = [];

    for (const pkg of context.packages) {
      const key = this.packageKey(pkg.ecosystem, pkg.packageName);
      resultMap.set(key, {
        packageName: pkg.packageName,
        ecosystem: pkg.ecosystem,
        status: 'indirect_no_evidence',
        snippets: [],
      });
      snippetKeyMap.set(key, new Set<string>());
    }

    let snippetsProduced = 0;
    let files: string[];

    try {
      files = await collectSourceFiles(context.projectPath);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        packages: context.packages.map((pkg) => ({
          packageName: pkg.packageName,
          ecosystem: pkg.ecosystem,
          status: 'analysis_error',
          snippets: [],
          notes: 'Failed to enumerate JS/TS source files',
        })),
        errors: [{ analyzer: this.name, ecosystem: context.ecosystem, error: message }],
        snippetsProduced: 0,
      };
    }

    for (const filePath of files) {
      if (snippetsProduced >= context.maxSnippetsTotal) break;

      let sourceText: string;
      try {
        sourceText = await readFile(filePath, 'utf-8');
      } catch (err: unknown) {
        errors.push({
          analyzer: this.name,
          ecosystem: context.ecosystem,
          error: `Failed to read ${filePath}: ${err instanceof Error ? err.message : String(err)}`,
        });
        continue;
      }

      let ast;
      try {
        ast = parse(sourceText, {
          sourceType: 'unambiguous',
          plugins: ['typescript', 'jsx'],
          allowReturnOutsideFunction: true,
        });
      } catch (err: unknown) {
        errors.push({
          analyzer: this.name,
          ecosystem: context.ecosystem,
          error: `Failed to parse ${filePath}: ${err instanceof Error ? err.message : String(err)}`,
        });
        continue;
      }

      const matchCandidates: MatchCandidate[] = [];
      const matchSeen = new Set<string>();
      const symbolToPackage = new Map<string, string>();

      const addMatch = (
        packageKey: string,
        line: number,
        matchKind: UsageSnippetMatchKind,
        calledSymbol?: string,
        confidence = 0.8,
      ) => {
        const candidateKey = `${packageKey}:${line}:${matchKind}:${calledSymbol ?? ''}`;
        if (matchSeen.has(candidateKey)) return;
        matchSeen.add(candidateKey);
        matchCandidates.push({ packageKey, line, matchKind, calledSymbol, confidence });
      };

      (traverse as unknown as (node: unknown, visitor: Record<string, unknown>) => void)(ast, {
        ImportDeclaration: (path: any) => {
          const source = path.node.source;
          if (!isStringLiteral(source)) return;

          const pkgKey = findPackageKey(resolveImportTarget(source.value), packageMap.byName);
          if (!pkgKey) return;

          addMatch(pkgKey, path.node.loc?.start.line ?? 1, 'import', undefined, 0.95);

          for (const specifier of path.node.specifiers) {
            if (
              isImportDefaultSpecifier(specifier) ||
              isImportNamespaceSpecifier(specifier) ||
              isImportSpecifier(specifier)
            ) {
              symbolToPackage.set(specifier.local.name, pkgKey);
            }
          }
        },

        ExportNamedDeclaration: (path: any) => {
          const source = path.node.source;
          if (!source || !isStringLiteral(source)) return;

          const pkgKey = findPackageKey(resolveImportTarget(source.value), packageMap.byName);
          if (!pkgKey) return;

          addMatch(pkgKey, path.node.loc?.start.line ?? 1, 'export_from', undefined, 0.85);
        },

        ExportAllDeclaration: (path: any) => {
          const source = path.node.source;
          if (!isStringLiteral(source)) return;

          const pkgKey = findPackageKey(resolveImportTarget(source.value), packageMap.byName);
          if (!pkgKey) return;

          addMatch(pkgKey, path.node.loc?.start.line ?? 1, 'export_from', undefined, 0.85);
        },

        VariableDeclarator: (path: any) => {
          const node = path.node;
          if (!isVariableDeclarator(node)) return;
          if (!node.init || !isCallExpression(node.init)) return;
          if (!isIdentifier(node.init.callee, { name: 'require' })) return;

          const firstArg = node.init.arguments[0];
          if (!firstArg || !isStringLiteral(firstArg)) return;

          const pkgKey = findPackageKey(resolveImportTarget(firstArg.value), packageMap.byName);
          if (!pkgKey) return;

          addMatch(pkgKey, node.loc?.start.line ?? 1, 'require', undefined, 0.95);

          for (const identifier of collectIdentifiers(node.id)) {
            symbolToPackage.set(identifier, pkgKey);
          }
        },

        CallExpression: (path: any) => {
          const node = path.node;

          if (isIdentifier(node.callee, { name: 'require' })) {
            const firstArg = node.arguments[0];
            if (firstArg && isStringLiteral(firstArg)) {
              const pkgKey = findPackageKey(resolveImportTarget(firstArg.value), packageMap.byName);
              if (pkgKey) {
                addMatch(pkgKey, node.loc?.start.line ?? 1, 'require', undefined, 0.9);
              }
            }
          }

          if (isImport(node.callee)) return;

          const callMatch = resolveCallMatch(node.callee as Expression, symbolToPackage);
          if (!callMatch) return;

          addMatch(
            callMatch.packageKey,
            node.loc?.start.line ?? 1,
            'call',
            callMatch.calledSymbol,
            0.75,
          );
        },

        ImportExpression: (path: any) => {
          const source = path.node.source;
          if (!isStringLiteral(source)) return;

          const pkgKey = findPackageKey(resolveImportTarget(source.value), packageMap.byName);
          if (!pkgKey) return;

          addMatch(pkgKey, path.node.loc?.start.line ?? 1, 'dynamic_import', undefined, 0.9);
        },
      });

      for (const candidate of matchCandidates) {
        if (snippetsProduced >= context.maxSnippetsTotal) break;

        const packageResult = resultMap.get(candidate.packageKey);
        if (!packageResult) continue;
        if (packageResult.snippets.length >= context.maxSnippetsPerPackage) continue;

        const snippet = buildSnippet({
          projectPath: context.projectPath,
          filePath,
          sourceText,
          line: candidate.line,
          numContextLines: context.numContextLines,
          matchKind: candidate.matchKind,
          calledSymbol: candidate.calledSymbol,
          confidence: candidate.confidence,
        });

        const dedupeKey = `${snippet.filePath}:${snippet.startLine}:${snippet.endLine}:${snippet.matchKind}:${snippet.calledSymbol ?? ''}`;
        const packageSnippetKeys = snippetKeyMap.get(candidate.packageKey);
        if (!packageSnippetKeys || packageSnippetKeys.has(dedupeKey)) continue;

        packageSnippetKeys.add(dedupeKey);
        packageResult.snippets.push(snippet);
        snippetsProduced++;
      }
    }

    for (const result of resultMap.values()) {
      result.snippets = dedupeSnippets(result.snippets);
      if (result.snippets.length > 0) {
        result.status = 'direct_evidence';
      } else if (files.length === 0) {
        result.notes = 'No JS/TS source files found for analysis';
      }
    }

    return {
      packages: Array.from(resultMap.values()),
      errors,
      snippetsProduced,
    };
  }

  private buildPackageMaps(packages: VulnerablePackageInput[]): {
    byName: Map<string, Array<{ key: string; ecosystem: Ecosystem }>>;
  } {
    const byName = new Map<string, Array<{ key: string; ecosystem: Ecosystem }>>();

    for (const pkg of packages) {
      const key = this.packageKey(pkg.ecosystem, pkg.packageName);
      const existing = byName.get(pkg.packageName) ?? [];
      existing.push({ key, ecosystem: pkg.ecosystem });
      byName.set(pkg.packageName, existing);
    }

    return { byName };
  }

  private packageKey(ecosystem: Ecosystem, packageName: string): string {
    return `${ecosystem}::${packageName}`;
  }
}

async function collectSourceFiles(rootPath: string): Promise<string[]> {
  const files: string[] = [];

  async function walk(dirPath: string): Promise<void> {
    const entries = await readdir(dirPath, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = join(dirPath, entry.name);

      if (entry.isDirectory()) {
        if (IGNORED_DIRS.has(entry.name)) continue;
        await walk(fullPath);
        continue;
      }

      if (!entry.isFile()) continue;

      const ext = extensionOf(entry.name);
      if (!JS_EXTENSIONS.has(ext)) continue;

      files.push(fullPath);
    }
  }

  await walk(rootPath);
  return files;
}

function extensionOf(fileName: string): string {
  const index = fileName.lastIndexOf('.');
  return index === -1 ? '' : fileName.slice(index);
}

function resolveImportTarget(specifier: string): ImportTarget | null {
  if (
    specifier.startsWith('./') ||
    specifier.startsWith('../') ||
    specifier.startsWith('/') ||
    specifier.startsWith('file:') ||
    specifier.startsWith('http:') ||
    specifier.startsWith('https:') ||
    specifier.startsWith('data:')
  ) {
    return null;
  }

  if (specifier.startsWith('npm:')) {
    const packageName = parsePackageNameFromSpecifier(specifier.slice(4));
    return packageName ? { packageName, ecosystemHint: 'npm' } : null;
  }

  if (specifier.startsWith('jsr:')) {
    const packageName = parsePackageNameFromSpecifier(specifier.slice(4));
    return packageName ? { packageName, ecosystemHint: 'deno' } : null;
  }

  const packageName = parsePackageNameFromSpecifier(specifier);
  return packageName ? { packageName, ecosystemHint: 'npm' } : null;
}

function parsePackageNameFromSpecifier(rawSpecifier: string): string | null {
  const input = rawSpecifier.trim();
  if (!input) return null;

  if (input.startsWith('@')) {
    const scopedMatch = input.match(/^(@[^/]+\/[^/@]+)(?:@[^/]+)?(?:\/.*)?$/);
    return scopedMatch ? scopedMatch[1] : null;
  }

  const unscopedMatch = input.match(/^([^/@]+)(?:@[^/]+)?(?:\/.*)?$/);
  return unscopedMatch ? unscopedMatch[1] : null;
}

function findPackageKey(
  target: ImportTarget | null,
  packagesByName: Map<string, Array<{ key: string; ecosystem: Ecosystem }>>,
): string | null {
  if (!target) return null;

  const candidates = packagesByName.get(target.packageName);
  if (!candidates || candidates.length === 0) return null;

  if (target.ecosystemHint) {
    const exact = candidates.find((candidate) => candidate.ecosystem === target.ecosystemHint);
    if (exact) return exact.key;
  }

  return candidates[0].key;
}

function collectIdentifiers(pattern: unknown): string[] {
  if (isIdentifier(pattern as any)) return [(pattern as any).name as string];

  if (isObjectPattern(pattern as any)) {
    const objectPattern = pattern as any;
    const names: string[] = [];
    for (const prop of objectPattern.properties) {
      if (isRestElement(prop)) {
        names.push(...collectIdentifiers(prop.argument));
        continue;
      }

      if ('value' in prop) {
        names.push(...collectIdentifiers(prop.value));
      }
    }
    return names;
  }

  if (isArrayPattern(pattern as any)) {
    const arrayPattern = pattern as any;
    const names: string[] = [];
    for (const elem of arrayPattern.elements) {
      if (!elem) continue;
      names.push(...collectIdentifiers(elem));
    }
    return names;
  }

  if (isAssignmentPattern(pattern as any)) {
    return collectIdentifiers((pattern as any).left);
  }

  if (isRestElement(pattern as any)) {
    return collectIdentifiers((pattern as any).argument);
  }

  return [];
}

function resolveCallMatch(
  callee: Expression,
  symbolToPackage: Map<string, string>,
): { packageKey: string; calledSymbol: string } | null {
  const normalized = unwrapExpression(callee);

  if (isIdentifier(normalized)) {
    const packageKey = symbolToPackage.get(normalized.name);
    if (!packageKey) return null;
    return { packageKey, calledSymbol: normalized.name };
  }

  if (isMemberExpression(normalized) || isOptionalMemberExpression(normalized)) {
    return resolveMemberCallMatch(normalized, symbolToPackage);
  }

  return null;
}

function unwrapExpression(expression: Expression): Expression {
  if (isTSAsExpression(expression)) return unwrapExpression(expression.expression);
  if (isTSTypeAssertion(expression)) return unwrapExpression(expression.expression);
  if (isTSSatisfiesExpression(expression)) return unwrapExpression(expression.expression);
  if (isParenthesizedExpression(expression)) return unwrapExpression(expression.expression);
  return expression;
}

function resolveMemberCallMatch(
  memberExpression: import('@babel/types').MemberExpression | OptionalMemberExpression,
  symbolToPackage: Map<string, string>,
): { packageKey: string; calledSymbol: string } | null {
  const objectExpr = unwrapExpression(memberExpression.object as Expression);
  if (!isIdentifier(objectExpr)) return null;

  const packageKey = symbolToPackage.get(objectExpr.name);
  if (!packageKey) return null;

  const propertyName = propertyNameOf(memberExpression);
  if (!propertyName) {
    return { packageKey, calledSymbol: objectExpr.name };
  }

  return { packageKey, calledSymbol: `${objectExpr.name}.${propertyName}` };
}

function propertyNameOf(
  memberExpression: import('@babel/types').MemberExpression | OptionalMemberExpression,
): string | null {
  if (memberExpression.computed) {
    const prop = memberExpression.property;
    if (isStringLiteral(prop)) return prop.value;
    return null;
  }

  if (isIdentifier(memberExpression.property)) {
    return memberExpression.property.name;
  }

  if (isStringLiteral(memberExpression.property)) {
    return memberExpression.property.value;
  }

  return null;
}
