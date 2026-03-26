import { scan as scanProject, uploadToVerimu } from '../scan.js';
import { LockfileDiscovery } from './lockfile-discovery.js';
import { ConsoleReporter } from '../reporters/console.js';
import { renderPlatformScan } from '../reporters/platform.js';
import { basename } from 'path';
import type {
  DiscoveredProject,
  MultiProjectConfig,
  MultiProjectScanResult,
  VerimuReport,
  VerimuConfig,
} from '../core/types.js';

export class MultiProjectOrchestrator {
  private discovery = new LockfileDiscovery();
  private reporter = new ConsoleReporter();

  /**
   * Gets a display name for a project (uses directory name instead of "." for root)
   */
  private getDisplayName(project: DiscoveredProject, rootPath: string): string {
    if (project.relativePath === '.') {
      return basename(rootPath);
    }
    return project.relativePath;
  }

  /**
   * Discovers and scans all projects in a directory tree.
   */
  async scanAll(config: MultiProjectConfig): Promise<MultiProjectScanResult> {
    const startTime = Date.now();

    // Extract API settings
    const apiKey = config.apiKey;
    const apiBaseUrl = config.apiBaseUrl;

    // 1. Discover all projects
    console.log(`\nDiscovering projects in ${config.projectPath}...`);

    const projects = await this.discovery.discover({
      rootPath: config.projectPath,
      exclude: config.exclude,
    });

    if (projects.length === 0) {
      console.log('No projects with lockfiles found.');
      return {
        totalDiscovered: 0,
        successful: [],
        failed: [],
        skipped: [],
        durationMs: Date.now() - startTime,
      };
    }

    // If only one project found, treat as a normal single project (no group)
    const isSingleProject = projects.length === 1;

    // Auto-derive group name from root directory if not provided (only for multi-project)
    const groupName = isSingleProject
      ? config.groupName  // Only use explicit group name for single project
      : (config.groupName || basename(config.projectPath));

    console.log(`Found ${projects.length} project(s):\n`);
    for (const p of projects) {
      const displayName = this.getDisplayName(p, config.projectPath);
      console.log(`  • ${displayName} (${p.scannerType})`);
    }

    // Show grouping info only for multi-project scenarios
    if (!isSingleProject) {
      if (!config.groupName) {
        console.log(`\n  ℹ Auto-grouping projects as: "${groupName}"`);
        console.log('  (Use --group to specify a custom group name)\n');
      } else {
        console.log(`\n  ℹ Grouping projects as: "${groupName}"\n`);
      }
    } else {
      console.log('');
    }

    // 2. Scan projects sequentially
    const successful: Array<{ project: DiscoveredProject; report: VerimuReport }> = [];
    const failed: Array<{ project: DiscoveredProject; error: string }> = [];

    for (let i = 0; i < projects.length; i++) {
      const project = projects[i];
      const displayName = this.getDisplayName(project, config.projectPath);

      console.log('─'.repeat(60));
      console.log(`[${i + 1}/${projects.length}] Scanning: ${displayName}`);
      console.log('─'.repeat(60));
      console.log('');

      try {
        // Derive output path based on project location
        const sbomOutput = this.deriveSbomPath(project, config.sbomOutput);

        // Scan without uploading (like original CLI does)
        const report = await scanProject({
          ...config,
          projectPath: project.projectPath,
          sbomOutput,
          groupName, // Use auto-derived or user-provided group name
          apiKey: undefined, // Don't upload in scan, do it separately
        });

        // Print detailed report
        console.log(this.reporter.report(report));

        // Upload to platform if API key provided
        if (apiKey) {
          console.log('');
          console.log(`  Syncing ${displayName} to Verimu platform...`);
          try {
            const uploadConfig: VerimuConfig = {
              ...config,
              projectPath: project.projectPath,
              groupName, // Use auto-derived or user-provided group name
              apiKey,
              apiBaseUrl,
            };
            const uploadResult = await uploadToVerimu(report, uploadConfig);

            if (uploadResult.projectCreated) {
              console.log(`  ✓ Project created: ${displayName}`);
            }
            console.log(`  ✓ ${uploadResult.totalDependencies} dependencies tracked`);
            console.log(renderPlatformScan(displayName, uploadResult));
            console.log(`  ✓ Dashboard: ${uploadResult.dashboardUrl}`);
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            console.log(`  ⚠ Platform sync failed: ${msg}`);
            console.log('  Your SBOM was still generated locally. You can upload it manually.');
          }
        }

        console.log('');
        successful.push({ project, report });
      } catch (error) {
        const errorMsg = error instanceof Error ? error.message : String(error);
        console.log(`  ✗ Failed: ${errorMsg}`);
        console.log('');

        failed.push({ project, error: errorMsg });

        // Stop on first error (no continue-on-error support)
        throw error;
      }
    }

    // 3. Build result summary
    return {
      totalDiscovered: projects.length,
      successful,
      failed,
      skipped: [],
      durationMs: Date.now() - startTime,
    };
  }

  /**
   * Derives SBOM output path for a project.
   * Places SBOMs in project directories by default.
   */
  private deriveSbomPath(project: DiscoveredProject, configOutput?: string): string {
    if (configOutput) {
      // If user specified output, use it as base and add project path
      const base = configOutput.replace(/\.cdx\.json$/, '');
      const sanitized = project.relativePath.replace(/[/\\]/g, '-');
      return `${base}.${sanitized}.cdx.json`;
    }

    // Default: place SBOM in project directory
    return `${project.projectPath}/sbom.cdx.json`;
  }
}
