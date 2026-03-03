import { randomUUID } from 'crypto';
import type { SbomGenerator } from './generator.interface.js';
import type { ScanResult, Sbom, SbomFormat } from '../core/types.js';
import {
  DEFAULT_TOOL_VERSION,
  VERIMU_TOOL_NAME,
  extractProjectName,
  normalizeDependencies,
} from './shared.js';

const SPDX_VERSION = '2.3';

/** Generates SPDX 2.3 JSON SBOMs. */
export class SpdxJsonGenerator implements SbomGenerator {
  readonly format: SbomFormat = 'spdx-json';

  generate(scanResult: ScanResult, toolVersion: string = DEFAULT_TOOL_VERSION): Sbom {
    const timestamp = new Date().toISOString();
    const projectName = extractProjectName(scanResult.projectPath);
    const rootPackageId = 'SPDXRef-Package-root';
    const dependencies = normalizeDependencies(scanResult.dependencies);

    const document = {
      spdxVersion: `SPDX-${SPDX_VERSION}`,
      dataLicense: 'CC0-1.0',
      SPDXID: 'SPDXRef-DOCUMENT',
      name: `${projectName}-sbom`,
      documentNamespace: `https://verimu.com/spdxdocs/${projectName}-${randomUUID()}`,
      creationInfo: {
        created: timestamp,
        creators: [`Tool: ${VERIMU_TOOL_NAME}@${toolVersion}`],
      },
      documentDescribes: [rootPackageId],
      packages: [
        {
          name: projectName,
          SPDXID: rootPackageId,
          versionInfo: 'NOASSERTION',
          supplier: `Organization: ${projectName}`,
          downloadLocation: 'NOASSERTION',
          filesAnalyzed: false,
          licenseConcluded: 'NOASSERTION',
          licenseDeclared: 'NOASSERTION',
          primaryPackagePurpose: 'APPLICATION',
        },
        ...dependencies.map((dep, index) => ({
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
        ...dependencies.map((_dep, index) => ({
          spdxElementId: rootPackageId,
          relationshipType: 'DEPENDS_ON',
          relatedSpdxElement: `SPDXRef-Package-${index + 1}`,
        })),
      ],
    };

    return {
      format: 'spdx-json',
      specVersion: SPDX_VERSION,
      content: JSON.stringify(document, null, 2),
      componentCount: scanResult.dependencies.length,
      generatedAt: timestamp,
    };
  }
}

