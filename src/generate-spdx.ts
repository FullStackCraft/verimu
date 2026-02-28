import { randomUUID } from 'crypto';
import type {
  GenerateSbomInput,
  GenerateSpdxSbomResult,
} from './core/types.js';
import {
  DEFAULT_PROJECT_VERSION,
  VERIMU_TOOL_NAME,
  normalizeDependencies,
} from './sbom/shared.js';

const SPDX_VERSION = '2.3';

/**
 * Generates an SPDX 2.3 JSON document from structured dependency data.
 *
 * This is a pure function with no filesystem or network access.
 */
export function generateSpdxSbom(input: GenerateSbomInput): GenerateSpdxSbomResult {
  const {
    projectName,
    projectVersion = DEFAULT_PROJECT_VERSION,
    dependencies,
  } = input;

  const timestamp = new Date().toISOString();
  const resolvedDeps = normalizeDependencies(dependencies);
  const rootPackageId = 'SPDXRef-Package-root';

  const spdx = {
    spdxVersion: `SPDX-${SPDX_VERSION}`,
    dataLicense: 'CC0-1.0',
    SPDXID: 'SPDXRef-DOCUMENT',
    name: `${projectName}-sbom`,
    documentNamespace: `https://verimu.com/spdxdocs/${projectName}-${randomUUID()}`,
    creationInfo: {
      created: timestamp,
      creators: [`Tool: ${VERIMU_TOOL_NAME}`],
    },
    documentDescribes: [rootPackageId],
    packages: [
      {
        name: projectName,
        SPDXID: rootPackageId,
        versionInfo: projectVersion,
        supplier: `Organization: ${projectName}`,
        downloadLocation: 'NOASSERTION',
        filesAnalyzed: false,
        licenseConcluded: 'NOASSERTION',
        licenseDeclared: 'NOASSERTION',
        primaryPackagePurpose: 'APPLICATION',
      },
      ...resolvedDeps.map((dep, index) => ({
        name: dep.name,
        SPDXID: `SPDXRef-Package-${index + 1}`,
        versionInfo: dep.version,
        supplier: `Organization: ${dep.supplierName}`,
        downloadLocation: 'NOASSERTION',
        filesAnalyzed: false,
        licenseConcluded: 'NOASSERTION',
        licenseDeclared: 'NOASSERTION',
        primaryPackagePurpose: 'LIBRARY',
        externalRefs: [
          {
            referenceCategory: 'PACKAGE-MANAGER',
            referenceType: 'purl',
            referenceLocator: dep.purl,
          },
        ],
      })),
    ],
    relationships: [
      {
        spdxElementId: 'SPDXRef-DOCUMENT',
        relationshipType: 'DESCRIBES',
        relatedSpdxElement: rootPackageId,
      },
      ...resolvedDeps.map((_dep, index) => ({
        spdxElementId: rootPackageId,
        relationshipType: 'DEPENDS_ON',
        relatedSpdxElement: `SPDXRef-Package-${index + 1}`,
      })),
    ],
  };

  const content = JSON.stringify(spdx, null, 2);

  return {
    sbom: spdx,
    content,
    componentCount: resolvedDeps.length,
    specVersion: SPDX_VERSION,
    generatedAt: timestamp,
  };
}

