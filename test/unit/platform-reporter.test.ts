import { describe, it, expect } from 'vitest';
import { renderPlatformScan } from '../../src/reporters/platform.js';

describe('renderPlatformScan()', () => {
  it('treats null vulnerability arrays as an empty backend result', () => {
    const result: Parameters<typeof renderPlatformScan>[1] = {
      projectId: 'project-1',
      projectCreated: false,
      totalDependencies: 1,
      vulnerableDependencies: 0,
      dashboardUrl: 'https://app.verimu.com/dashboard/projects/project-1',
      scanResponse: {
        project: {
          id: 'project-1',
          name: 'verimu.com',
        },
        scan_results: [
          {
            dependency_id: 'dep-1',
            dependency_name: 'debug',
            version: '4.4.3',
            vulnerabilities: null,
          },
        ],
        summary: {
          total_dependencies: 1,
          vulnerable_dependencies: 0,
        },
      },
    };

    expect(() => renderPlatformScan('/tmp/verimu.com', result)).not.toThrow();

    const output = renderPlatformScan('/tmp/verimu.com', result);
    expect(output).toContain('VERIMU PLATFORM SCAN RESULTS');
    expect(output).toContain('No platform vulnerabilities found');
    expect(output).toContain('Total: 0');
  });

  it('renders backend vulnerabilities when they are present', () => {
    const result: Parameters<typeof renderPlatformScan>[1] = {
      projectId: 'project-1',
      projectCreated: false,
      totalDependencies: 1,
      vulnerableDependencies: 1,
      dashboardUrl: 'https://app.verimu.com/dashboard/projects/project-1',
      scanResponse: {
        project: {
          id: 'project-1',
          name: 'verimu.com',
        },
        scan_results: [
          {
            dependency_id: 'dep-1',
            dependency_name: 'debug',
            version: '4.4.3',
            vulnerabilities: [
              {
                cve_id: 'CVE-2026-1234',
                severity: 'medium',
                summary: 'Prototype pollution in debug',
                fixed_version: '4.4.4',
              },
            ],
          },
        ],
        summary: {
          total_dependencies: 1,
          vulnerable_dependencies: 1,
        },
      },
    };

    const output = renderPlatformScan('/tmp/verimu.com', result);
    expect(output).toContain('[MED]');
    expect(output).toContain('CVE-2026-1234');
    expect(output).toContain('debug@4.4.3 → fix: 4.4.4');
    expect(output).toContain('Total: 1');
  });
});
