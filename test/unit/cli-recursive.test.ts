import { describe, it, expect } from 'vitest';
import { parseArgs } from '../../src/cli.js';

describe('CLI recursive flags', () => {
  it('recursive is true by default', () => {
    const args = parseArgs(['node', 'verimu', 'scan']);
    expect(args.recursive).toBe(true);
  });

  it('parses --no-recursive flag', () => {
    const args = parseArgs(['node', 'verimu', 'scan', '--no-recursive']);
    expect(args.recursive).toBe(false);
  });

  it('parses --not-recursive flag', () => {
    const args = parseArgs(['node', 'verimu', 'scan', '--not-recursive']);
    expect(args.recursive).toBe(false);
  });

  it('parses --exclude with comma-separated patterns', () => {
    const args = parseArgs(['node', 'verimu', 'scan', '--exclude', 'legacy/*,deprecated/*']);
    expect(args.exclude).toEqual(['legacy/*', 'deprecated/*']);
  });

  it('throws for missing --exclude value', () => {
    expect(() => parseArgs(['node', 'verimu', 'scan', '--exclude'])).toThrow(
      '--exclude requires a comma-separated list of patterns'
    );
  });

  it('combines flags with existing flags', () => {
    const args = parseArgs([
      'node',
      'verimu',
      'scan',
      '--path',
      './monorepo',
      '--group-name',
      'my-app',
      '--exclude',
      'legacy/*',
      '--skip-cve',
    ]);

    expect(args.recursive).toBe(true);
    expect(args.projectPath).toBe('./monorepo');
    expect(args.groupName).toBe('my-app');
    expect(args.exclude).toEqual(['legacy/*']);
    expect(args.skipCveCheck).toBe(true);
  });

  it('exclude is undefined when not provided', () => {
    const args = parseArgs(['node', 'verimu', 'scan']);
    expect(args.exclude).toBeUndefined();
  });
});
