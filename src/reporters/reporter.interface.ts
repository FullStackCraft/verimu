import type { VerimuReport } from '../core/types.js';

/** Interface for outputting scan results */
export interface Reporter {
  readonly name: string;
  report(result: VerimuReport): string;
}
