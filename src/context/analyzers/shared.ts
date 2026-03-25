import { readdir, readFile } from 'fs/promises';
import { join } from 'path';
import type { Ecosystem, UsageContextError, UsageSnippetMatchKind } from '../../core/types.js';
import { buildSnippet, dedupeSnippets } from '../snippet-extractor.js';
import type {
  AnalyzerRunContext,
  AnalyzerRunResult,
  PackageAnalysisResult,
  VulnerablePackageInput,
} from './analyzer.interface.js';

const DEFAULT_IGNORED_DIRS = new Set([
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
  'vendor',
  '.venv',
  'venv',
  'target',
  'bin',
  'obj',
]);

export interface MatchCandidate {
  packageKey: string;
  line: number;
  matchKind: UsageSnippetMatchKind;
  calledSymbol?: string;
  confidence?: number;
}

export interface AnalyzerRuntimeState {
  resultMap: Map<string, PackageAnalysisResult>;
  snippetKeyMap: Map<string, Set<string>>;
  errors: UsageContextError[];
  snippetsProduced: number;
}

export function packageKey(ecosystem: string, packageName: string): string {
  return `${ecosystem}::${packageName}`;
}

export function initState(packages: VulnerablePackageInput[]): AnalyzerRuntimeState {
  const resultMap = new Map<string, PackageAnalysisResult>();
  const snippetKeyMap = new Map<string, Set<string>>();

  for (const pkg of packages) {
    const key = packageKey(pkg.ecosystem, pkg.packageName);
    resultMap.set(key, {
      packageName: pkg.packageName,
      ecosystem: pkg.ecosystem,
      status: 'indirect_no_evidence',
      snippets: [],
    });
    snippetKeyMap.set(key, new Set<string>());
  }

  return {
    resultMap,
    snippetKeyMap,
    errors: [],
    snippetsProduced: 0,
  };
}

export function errorResultFromMessage(
  context: AnalyzerRunContext,
  analyzerName: string,
  message: string,
  notes: string,
): AnalyzerRunResult {
  return {
    packages: context.packages.map((pkg) => ({
      packageName: pkg.packageName,
      ecosystem: pkg.ecosystem,
      status: 'analysis_error',
      snippets: [],
      notes,
    })),
    errors: [{ analyzer: analyzerName, ecosystem: context.ecosystem, error: message }],
    snippetsProduced: 0,
  };
}

export function toAnalyzerResult(state: AnalyzerRuntimeState): AnalyzerRunResult {
  for (const result of state.resultMap.values()) {
    result.snippets = dedupeSnippets(result.snippets);
    if (result.snippets.length > 0) {
      result.status = 'direct_evidence';
    }
  }

  return {
    packages: Array.from(state.resultMap.values()),
    errors: state.errors,
    snippetsProduced: state.snippetsProduced,
  };
}

export async function collectSourceFiles(
  rootPath: string,
  extensions: Set<string>,
  ignoredDirs: Set<string> = DEFAULT_IGNORED_DIRS,
): Promise<string[]> {
  const files: string[] = [];

  async function walk(dirPath: string): Promise<void> {
    const entries = await readdir(dirPath, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = join(dirPath, entry.name);

      if (entry.isDirectory()) {
        if (ignoredDirs.has(entry.name)) continue;
        await walk(fullPath);
        continue;
      }

      if (!entry.isFile()) continue;
      if (!extensions.has(extensionOf(entry.name))) continue;
      files.push(fullPath);
    }
  }

  await walk(rootPath);
  return files;
}

export async function readSourceFile(
  analyzerName: string,
  ecosystem: Ecosystem,
  filePath: string,
  errors: UsageContextError[],
): Promise<string | null> {
  try {
    return await readFile(filePath, 'utf-8');
  } catch (err: unknown) {
    errors.push({
      analyzer: analyzerName,
      ecosystem,
      error: `Failed to read ${filePath}: ${err instanceof Error ? err.message : String(err)}`,
    });
    return null;
  }
}

export function addCandidate(
  context: AnalyzerRunContext,
  state: AnalyzerRuntimeState,
  filePath: string,
  sourceText: string,
  candidate: MatchCandidate,
): void {
  if (state.snippetsProduced >= context.maxSnippetsTotal) return;

  const packageResult = state.resultMap.get(candidate.packageKey);
  if (!packageResult) return;
  if (packageResult.snippets.length >= context.maxSnippetsPerPackage) return;

  const snippet = buildSnippet({
    projectPath: context.projectPath,
    filePath,
    sourceText,
    line: candidate.line,
    numContextLines: context.numContextLines,
    matchKind: candidate.matchKind,
    calledSymbol: candidate.calledSymbol,
    confidence: candidate.confidence ?? 0.8,
  });

  const dedupeKey = `${snippet.filePath}:${snippet.startLine}:${snippet.endLine}:${snippet.matchKind}:${snippet.calledSymbol ?? ''}`;
  const packageSnippetKeys = state.snippetKeyMap.get(candidate.packageKey);
  if (!packageSnippetKeys || packageSnippetKeys.has(dedupeKey)) return;

  packageSnippetKeys.add(dedupeKey);
  packageResult.snippets.push(snippet);
  state.snippetsProduced += 1;
}

export function extensionOf(fileName: string): string {
  const index = fileName.lastIndexOf('.');
  return index === -1 ? '' : fileName.slice(index).toLowerCase();
}

export function basePackageName(name: string): string {
  const slash = name.includes('/') ? name.split('/').at(-1) ?? name : name;
  const colon = slash.includes(':') ? slash.split(':').at(-1) ?? slash : slash;
  return colon;
}

export function toIdentifierToken(value: string): string {
  return value
    .replace(/[^A-Za-z0-9_]/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toLowerCase();
}

export function uniqueTokens(values: string[]): string[] {
  const result: string[] = [];
  const seen = new Set<string>();

  for (const value of values) {
    const trimmed = value.trim();
    if (!trimmed) continue;
    const key = trimmed.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(trimmed);
  }

  return result;
}
