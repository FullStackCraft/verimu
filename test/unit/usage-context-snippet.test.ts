import { describe, it, expect } from 'vitest';
import {
  buildSnippet,
  normalizeNumContextLines,
} from '../../src/context/snippet-extractor.js';

describe('Usage context snippet extractor', () => {
  it('normalizes numContextLines with defaults and clamps', () => {
    expect(normalizeNumContextLines(undefined)).toBe(4);
    expect(normalizeNumContextLines(-3)).toBe(0);
    expect(normalizeNumContextLines(7.8)).toBe(7);
    expect(normalizeNumContextLines(999)).toBe(20);
  });

  it('builds snippets with configured context lines', () => {
    const source = [
      'line1',
      'line2',
      'import express from "express";',
      'line4',
      'line5',
    ].join('\n');

    const snippet = buildSnippet({
      projectPath: '/tmp/project',
      filePath: '/tmp/project/src/index.ts',
      sourceText: source,
      line: 3,
      numContextLines: 1,
      matchKind: 'import',
      confidence: 0.9,
    });

    expect(snippet.startLine).toBe(2);
    expect(snippet.endLine).toBe(4);
    expect(snippet.filePath).toBe('src/index.ts');
    expect(snippet.code).toContain('import express from "express";');
  });
});
