import { describe, expect, it } from 'vitest';
import { parseArgs } from '../../src/cli.js';

describe('CLI argument parsing', () => {
  it('parses --context-lines', () => {
    const args = parseArgs(['node', 'verimu', 'scan', '--context-lines', '8']);
    expect(args.contextLines).toBe(8);
  });

  it('parses --context-lines=<n>', () => {
    const args = parseArgs(['node', 'verimu', 'scan', '--context-lines=3']);
    expect(args.contextLines).toBe(3);
  });

  it('throws for invalid --context-lines value', () => {
    expect(() => parseArgs(['node', 'verimu', 'scan', '--context-lines', 'abc'])).toThrow(
      'Invalid --context-lines value',
    );
  });
});
