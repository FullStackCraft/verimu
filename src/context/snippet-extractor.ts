import { relative, sep } from 'path';
import type { UsageSnippet, UsageSnippetMatchKind } from '../core/types.js';

export const DEFAULT_NUM_CONTEXT_LINES = 4;
export const MIN_CONTEXT_LINES = 0;
export const MAX_CONTEXT_LINES = 20;

export function normalizeNumContextLines(value: number | undefined): number {
  if (!Number.isFinite(value)) {
    return DEFAULT_NUM_CONTEXT_LINES;
  }

  const rounded = Math.floor(value as number);
  if (rounded < MIN_CONTEXT_LINES) return MIN_CONTEXT_LINES;
  if (rounded > MAX_CONTEXT_LINES) return MAX_CONTEXT_LINES;
  return rounded;
}

export function buildSnippet(params: {
  projectPath: string;
  filePath: string;
  sourceText: string;
  line: number;
  numContextLines: number;
  matchKind: UsageSnippetMatchKind;
  calledSymbol?: string;
  confidence?: number;
}): UsageSnippet {
  const {
    projectPath,
    filePath,
    sourceText,
    line,
    numContextLines,
    matchKind,
    calledSymbol,
    confidence = 0.8,
  } = params;

  const lines = sourceText.split(/\r?\n/);
  const centerLine = Math.max(1, Math.min(line, Math.max(lines.length, 1)));
  const startLine = Math.max(1, centerLine - numContextLines);
  const endLine = Math.min(lines.length || 1, centerLine + numContextLines);
  const code = lines.slice(startLine - 1, endLine).join('\n');

  // 0-indexed offset of the matched line within the `code` string.
  // Both tuple values are equal for single-line matches (all current match kinds).
  const highlightOffset = centerLine - startLine;
  const highlight: [number, number] = [highlightOffset, highlightOffset];

  return {
    filePath: relative(projectPath, filePath).split(sep).join('/'),
    startLine,
    endLine,
    code,
    matchKind,
    calledSymbol,
    confidence,
    highlight,
  };
}

export function dedupeSnippets(snippets: UsageSnippet[]): UsageSnippet[] {
  const seen = new Set<string>();
  const result: UsageSnippet[] = [];

  for (const snippet of snippets) {
    const key = [
      snippet.filePath,
      snippet.startLine,
      snippet.endLine,
      snippet.matchKind,
      snippet.calledSymbol ?? '',
    ].join(':');

    if (seen.has(key)) continue;
    seen.add(key);
    result.push(snippet);
  }

  return result;
}
