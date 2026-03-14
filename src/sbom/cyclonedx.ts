import { randomUUID } from 'crypto';
import type { SbomGenerator } from './generator.interface.js';
import type { ScanResult, Sbom, SbomFormat, Dependency } from '../core/types.js';
import {
  DEFAULT_TOOL_VERSION,
  VERIMU_TOOL_DESCRIPTION,
  VERIMU_TOOL_NAME,
  VERIMU_TOOL_WEBSITE,
  deriveSupplierName,
  extractProjectName,
} from './shared.js';

/** Supported CycloneDX spec versions */
export type CycloneDxSpecVersion = '1.4' | '1.5' | '1.6' | '1.7';

const SCHEMA_URLS: Record<CycloneDxSpecVersion, string> = {
  '1.4': 'http://cyclonedx.org/schema/bom-1.4.schema.json',
  '1.5': 'http://cyclonedx.org/schema/bom-1.5.schema.json',
  '1.6': 'http://cyclonedx.org/schema/bom-1.6.schema.json',
  '1.7': 'http://cyclonedx.org/schema/bom-1.7.schema.json',
};

/**
 * Generates CycloneDX JSON SBOMs (versions 1.4 – 1.7).
 *
 * CycloneDX is the preferred SBOM format for CRA compliance.
 * Spec: https://cyclonedx.org/specification/overview/
 *
 * NTIA minimum elements are satisfied:
 *  - metadata.supplier (supplier of the root software)
 *  - components[].supplier (supplier of each dependency)
 *  - components[].name, version, purl, bom-ref
 *  - dependencies[] graph
 *
 * Schema differences handled per version:
 *  - 1.4: metadata.tools is a flat array of { vendor, name, version, ... }
 *  - 1.5+: metadata.tools is { components: [...] }
 */
export class CycloneDxGenerator implements SbomGenerator {
  readonly format: SbomFormat = 'cyclonedx-json';

  constructor(private readonly specVersion: CycloneDxSpecVersion = '1.7') { }

  generate(scanResult: ScanResult, toolVersion: string = DEFAULT_TOOL_VERSION): Sbom {
    const bom = this.buildBom(scanResult, toolVersion);
    const content = JSON.stringify(bom, null, 2);

    return {
      format: 'cyclonedx-json',
      specVersion: this.specVersion,
      content,
      componentCount: scanResult.dependencies.length,
      generatedAt: new Date().toISOString(),
    };
  }

  private buildBom(scanResult: ScanResult, toolVersion: string): CycloneDxBom {
    const projectName = extractProjectName(scanResult.projectPath);

    return {
      $schema: SCHEMA_URLS[this.specVersion],
      bomFormat: 'CycloneDX',
      specVersion: this.specVersion,
      serialNumber: `urn:uuid:${randomUUID()}`,
      version: 1,
      metadata: {
        timestamp: new Date().toISOString(),
        tools: this.buildTools(toolVersion),
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
        name: deriveSupplierName(dep.name),
      },
    };
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

  /**
   * Builds the tools metadata section.
   *
   * CycloneDX 1.4: tools is a flat array of { vendor, name, version, ... }
   * CycloneDX 1.5+: tools is an object { components: [...] }
   */
  private buildTools(toolVersion: string): CycloneDxTools {
    if (this.specVersion === '1.4') {
      return [
        {
          vendor: 'Verimu',
          name: VERIMU_TOOL_NAME,
          version: toolVersion,
          externalReferences: [{ type: 'website', url: VERIMU_TOOL_WEBSITE }],
        },
      ];
    }

    return {
      components: [
        {
          type: 'application',
          name: VERIMU_TOOL_NAME,
          version: toolVersion,
          description: VERIMU_TOOL_DESCRIPTION,
          supplier: { name: 'Verimu' },
          externalReferences: [{ type: 'website', url: VERIMU_TOOL_WEBSITE }],
        },
      ],
    };
  }
}

// ─── CycloneDX JSON Types ─────────────────────────────────────

interface OrganizationalEntity {
  name: string;
  url?: string[];
  contact?: Array<{ name?: string; email?: string; phone?: string }>;
}

/** tools format for CycloneDX 1.4 — a flat array of tool objects */
type CycloneDxToolsV14 = Array<{
  vendor?: string;
  name: string;
  version: string;
  externalReferences?: Array<{ type: string; url: string }>;
}>;

/** tools format for CycloneDX 1.5+ — object with a components array */
type CycloneDxToolsV15Plus = {
  components: Array<{
    type: string;
    name: string;
    version: string;
    description?: string;
    supplier?: OrganizationalEntity;
    externalReferences?: Array<{ type: string; url: string }>;
  }>;
};

type CycloneDxTools = CycloneDxToolsV14 | CycloneDxToolsV15Plus;

interface CycloneDxBom {
  $schema: string;
  bomFormat: string;
  specVersion: string;
  serialNumber: string;
  version: number;
  metadata: {
    timestamp: string;
    tools: CycloneDxTools;
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
