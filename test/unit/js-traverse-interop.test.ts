import { describe, expect, it } from 'vitest';
import { resolveTraverseFunction } from '../../src/context/analyzers/js-ast-analyzer.js';

describe('resolveTraverseFunction()', () => {
  it('accepts direct function export', () => {
    const traverse = (_ast: unknown, _visitor: Record<string, unknown>) => {};
    const resolved = resolveTraverseFunction(traverse);
    expect(typeof resolved).toBe('function');
  });

  it('accepts default function export wrapper', () => {
    const traverse = (_ast: unknown, _visitor: Record<string, unknown>) => {};
    const resolved = resolveTraverseFunction({ default: traverse });
    expect(typeof resolved).toBe('function');
  });

  it('returns null for invalid export shape', () => {
    const resolved = resolveTraverseFunction({ default: { not: 'a function' } });
    expect(resolved).toBeNull();
  });
});

