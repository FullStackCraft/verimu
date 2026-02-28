import { randomUUID } from 'crypto';
import type {
  GenerateSbomInput,
  GenerateSbomResult,
} from './core/types.js';
import {
  DEFAULT_PROJECT_VERSION,
  VERIMU_TOOL_DESCRIPTION,
  VERIMU_TOOL_NAME,
  VERIMU_TOOL_WEBSITE,
  buildPurl,
  normalizeDependencies,
} from './sbom/shared.js';

/**
 * Generates an NTIA-compliant CycloneDX 1.7 SBOM from structured dependency data.
 *
 * This is a **pure function** — no filesystem access, no network calls, no side effects.
 * It takes a project name, version, and list of dependencies, and returns a complete
 * CycloneDX 1.7 JSON SBOM that passes NTIA minimum-element validation.
 *
 * @example
 * ```ts
 * import { generateSbom } from 'verimu';
 *
 * const result = generateSbom({
 *   projectName: 'my-app',
 *   projectVersion: '1.0.0',
 *   dependencies: [
 *     { name: 'express', version: '4.18.2', ecosystem: 'npm' },
 *     { name: '@types/node', version: '20.11.5', ecosystem: 'npm', direct: false },
 *   ],
 * });
 *
 * console.log(result.componentCount); // 2
 * console.log(result.content);        // formatted JSON string
 * ```
 */
export function generateSbom(input: GenerateSbomInput): GenerateSbomResult {
  const {
    projectName,
    projectVersion = DEFAULT_PROJECT_VERSION,
    dependencies,
  } = input;

  const timestamp = new Date().toISOString();
  const resolvedDeps = normalizeDependencies(dependencies);

  const rootPurl = buildPurl(projectName, projectVersion, 'npm');

  const sbom = {
    $schema: 'http://cyclonedx.org/schema/bom-1.7.schema.json',
    bomFormat: 'CycloneDX',
    specVersion: '1.7',
    serialNumber: `urn:uuid:${randomUUID()}`,
    version: 1,
    metadata: {
      timestamp,
      tools: {
        components: [
          {
            type: 'application',
            name: VERIMU_TOOL_NAME,
            version: '0.0.1',
            description: VERIMU_TOOL_DESCRIPTION,
            supplier: { name: 'Verimu' },
            externalReferences: [
              { type: 'website', url: VERIMU_TOOL_WEBSITE },
            ],
          },
        ],
      },
      supplier: { name: projectName },
      component: {
        type: 'application',
        name: projectName,
        version: projectVersion,
        'bom-ref': rootPurl,
        supplier: { name: projectName },
      },
    },
    components: resolvedDeps.map((dep) => ({
      type: 'library',
      name: dep.name,
      version: dep.version,
      purl: dep.purl,
      'bom-ref': dep.purl,
      scope: dep.direct ? 'required' : 'optional',
      supplier: { name: dep.supplierName },
    })),
    dependencies: [
      {
        ref: rootPurl,
        dependsOn: resolvedDeps.map((d) => d.purl),
      },
    ],
  };

  const content = JSON.stringify(sbom, null, 2);

  return {
    sbom,
    content,
    componentCount: resolvedDeps.length,
    specVersion: '1.7',
    generatedAt: timestamp,
  };
}
