import { randomUUID } from 'crypto';
import type {
  GenerateSbomInput,
  GenerateSbomResult,
  SbomDependency,
  Ecosystem,
} from './core/types.js';

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
    projectVersion = '0.0.0',
    dependencies,
  } = input;

  const timestamp = new Date().toISOString();

  // Resolve PURLs for any deps that don't have one
  const resolvedDeps = dependencies.map((dep) => ({
    ...dep,
    direct: dep.direct ?? true,
    purl: dep.purl ?? buildPurl(dep.name, dep.version, dep.ecosystem),
  }));

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
            name: 'verimu',
            version: '0.0.1',
            description: 'Verimu CRA Compliance Scanner',
            supplier: { name: 'Verimu' },
            externalReferences: [
              { type: 'website', url: 'https://verimu.com' },
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
      supplier: { name: deriveSupplierName(dep.name) },
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

// ─── Internal helpers ───────────────────────────────────────────

const PURL_TYPE_MAP: Record<Ecosystem, string> = {
  npm: 'npm',
  nuget: 'nuget',
  cargo: 'cargo',
  maven: 'maven',
  pip: 'pypi',
  go: 'golang',
  ruby: 'gem',
  composer: 'composer',
  deno: 'deno',
};

/**
 * Builds a Package URL (purl) per the purl spec.
 *
 * For npm scoped packages, the @ prefix is percent-encoded as %40:
 *   @types/node@20.11.5 → pkg:npm/%40types/node@20.11.5
 *
 * See: https://github.com/package-url/purl-spec/blob/main/types-doc/npm-definition.md
 */
function buildPurl(name: string, version: string, ecosystem: Ecosystem): string {
  const type = PURL_TYPE_MAP[ecosystem] || ecosystem;

  if (ecosystem === 'npm' && name.startsWith('@')) {
    return `pkg:${type}/%40${name.slice(1)}@${version}`;
  }

  return `pkg:${type}/${name}@${version}`;
}

/**
 * Derives supplier name from a package name.
 * Scoped packages: "@vue/reactivity" → "@vue"
 * Unscoped packages: "express" → "express"
 */
function deriveSupplierName(packageName: string): string {
  if (packageName.startsWith('@')) {
    return packageName.split('/')[0];
  }
  return packageName;
}
