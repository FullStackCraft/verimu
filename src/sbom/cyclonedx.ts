import { randomUUID } from 'crypto';
import type { SbomGenerator } from './generator.interface.js';
import type { ScanResult, Sbom, SbomFormat, Dependency } from '../core/types.js';

/**
 * Generates CycloneDX 1.7 JSON SBOMs.
 *
 * CycloneDX is the preferred SBOM format for CRA compliance.
 * Spec: https://cyclonedx.org/docs/1.7/json/
 *
 * NTIA minimum elements are satisfied:
 *  - metadata.supplier (supplier of the root software)
 *  - components[].supplier (supplier of each dependency)
 *  - components[].name, version, purl, bom-ref
 *  - dependencies[] graph
 */
export class CycloneDxGenerator implements SbomGenerator {
  readonly format: SbomFormat = 'cyclonedx-json';

  generate(scanResult: ScanResult, toolVersion: string = '0.1.0'): Sbom {
    const bom = this.buildBom(scanResult, toolVersion);
    const content = JSON.stringify(bom, null, 2);

    return {
      format: 'cyclonedx-json',
      specVersion: '1.7',
      content,
      componentCount: scanResult.dependencies.length,
      generatedAt: new Date().toISOString(),
    };
  }

  private buildBom(scanResult: ScanResult, toolVersion: string): CycloneDxBom {
    const projectName = this.extractProjectName(scanResult.projectPath);

    return {
      $schema: 'http://cyclonedx.org/schema/bom-1.7.schema.json',
      bomFormat: 'CycloneDX',
      specVersion: '1.7',
      serialNumber: `urn:uuid:${randomUUID()}`,
      version: 1,
      metadata: {
        timestamp: new Date().toISOString(),
        tools: {
          components: [
            {
              type: 'application',
              name: 'verimu',
              version: toolVersion,
              description: 'Verimu CRA Compliance Scanner',
              supplier: { name: 'Verimu' },
              externalReferences: [
                {
                  type: 'website',
                  url: 'https://verimu.com',
                },
              ],
            },
          ],
        },
        // NTIA: metadata.supplier — the org supplying the root software
        supplier: {
          name: projectName,
        },
        component: {
          type: 'application',
          name: projectName,
          'bom-ref': 'root-component',
          supplier: { name: projectName },
        },
      },
      components: scanResult.dependencies.map((dep) => this.toComponent(dep)),
      dependencies: this.buildDependencyGraph(scanResult),
    };
  }

  /** Converts a Verimu Dependency to a CycloneDX component */
  private toComponent(dep: Dependency): CycloneDxComponent {
    return {
      type: 'library',
      name: dep.name,
      version: dep.version,
      purl: dep.purl,
      'bom-ref': dep.purl,
      scope: dep.direct ? 'required' : 'optional',
      // NTIA: component.supplier — derived from npm scope or package name
      supplier: {
        name: this.deriveSupplierName(dep.name),
      },
    };
  }

  /**
   * Derives a supplier name from a package name.
   *
   * For scoped packages like "@vue/reactivity" → "@vue"
   * For unscoped packages like "express" → "express"
   *
   * This is the same heuristic used by Syft, Trivy, and other SBOM tools
   * when registry metadata (author/publisher) isn't available from the lockfile.
   */
  private deriveSupplierName(packageName: string): string {
    if (packageName.startsWith('@')) {
      // Scoped package: "@scope/name" → "@scope"
      const scope = packageName.split('/')[0];
      return scope;
    }
    return packageName;
  }

  /**
   * Builds the dependency graph section of the SBOM.
   *
   * The root component depends on all dependencies (direct + transitive).
   * This ensures a single root node in the graph, which NTIA validators expect.
   *
   * We include ALL deps under root (not just direct) because from a flat lockfile
   * we can't reliably reconstruct which transitive dep belongs to which direct dep.
   * This is still valid per the CycloneDX spec — it represents a complete but flat
   * dependency relationship.
   */
  private buildDependencyGraph(scanResult: ScanResult): CycloneDxDependencyEntry[] {
    const allDepPurls = scanResult.dependencies.map((d) => d.purl);

    return [
      {
        ref: 'root-component',
        dependsOn: allDepPurls,
      },
    ];
  }

  /** Extracts project name from path */
  private extractProjectName(projectPath: string): string {
    const parts = projectPath.replace(/\\/g, '/').split('/');
    return parts[parts.length - 1] || 'unknown-project';
  }
}

// ─── CycloneDX 1.7 JSON Types ──────────────────────────────────

interface OrganizationalEntity {
  name: string;
  url?: string[];
  contact?: Array<{ name?: string; email?: string; phone?: string }>;
}

interface CycloneDxBom {
  $schema: string;
  bomFormat: string;
  specVersion: string;
  serialNumber: string;
  version: number;
  metadata: {
    timestamp: string;
    tools: {
      components: Array<{
        type: string;
        name: string;
        version: string;
        description?: string;
        supplier?: OrganizationalEntity;
        externalReferences?: Array<{ type: string; url: string }>;
      }>;
    };
    supplier: OrganizationalEntity;
    component: {
      type: string;
      name: string;
      'bom-ref': string;
      supplier: OrganizationalEntity;
    };
  };
  components: CycloneDxComponent[];
  dependencies: CycloneDxDependencyEntry[];
}

interface CycloneDxComponent {
  type: string;
  name: string;
  version: string;
  purl: string;
  'bom-ref': string;
  scope?: string;
  supplier: OrganizationalEntity;
}

interface CycloneDxDependencyEntry {
  ref: string;
  dependsOn: string[];
}
