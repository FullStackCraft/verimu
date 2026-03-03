import { describe, it, expect } from 'vitest';
import path from 'path';
import { NpmScanner } from '../../src/scanners/npm/npm-scanner.js';
import { SpdxJsonGenerator } from '../../src/sbom/spdx.js';
import { SwidTagGenerator } from '../../src/sbom/swid.js';
import { generateSpdxSbom } from '../../src/generate-spdx.js';
import { generateSwidTag } from '../../src/generate-swid.js';

const FIXTURES = path.resolve(__dirname, '../fixtures');

describe('SpdxJsonGenerator', () => {
  it('generates SPDX 2.3 JSON with root and dependency relationships', async () => {
    const scanner = new NpmScanner();
    const lockfilePath = path.join(FIXTURES, 'node-api', 'package-lock.json');
    const scanResult = await scanner.scan(path.join(FIXTURES, 'node-api'), lockfilePath);

    const sbom = new SpdxJsonGenerator().generate(scanResult, '0.1.0');
    const document = JSON.parse(sbom.content);

    expect(sbom.format).toBe('spdx-json');
    expect(sbom.specVersion).toBe('2.3');
    expect(document.spdxVersion).toBe('SPDX-2.3');
    expect(document.packages.length).toBe(scanResult.dependencies.length + 1);
    expect(document.relationships).toContainEqual({
      spdxElementId: 'SPDXRef-DOCUMENT',
      relationshipType: 'DESCRIBES',
      relatedSpdxElement: 'SPDXRef-Package-root',
    });
  });
});

describe('SwidTagGenerator', () => {
  it('generates a minimal SWID XML tag for the root product', async () => {
    const scanner = new NpmScanner();
    const lockfilePath = path.join(FIXTURES, 'node-api', 'package-lock.json');
    const scanResult = await scanner.scan(path.join(FIXTURES, 'node-api'), lockfilePath);

    const sbom = new SwidTagGenerator().generate(scanResult, '0.1.0');

    expect(sbom.format).toBe('swid-xml');
    expect(sbom.specVersion).toContain('19770-2');
    expect(sbom.content).toContain('<SoftwareIdentity');
    expect(sbom.content).toContain('name="node-api"');
    expect(sbom.content).toContain('TODO: Consider adding dependency/package evidence');
  });
});

describe('Pure multi-format generators', () => {
  const input = {
    projectName: 'my-app',
    projectVersion: '1.2.3',
    dependencies: [
      { name: 'express', version: '4.18.2', ecosystem: 'npm' as const },
      { name: '@types/node', version: '20.11.5', ecosystem: 'npm' as const, direct: false },
    ],
  };

  it('generates SPDX JSON from structured dependency input', () => {
    const result = generateSpdxSbom(input);
    const document = JSON.parse(result.content);

    expect(result.specVersion).toBe('2.3');
    expect(document.spdxVersion).toBe('SPDX-2.3');
    expect(document.packages[0].versionInfo).toBe('1.2.3');
    expect(document.packages[2].externalRefs[0].referenceLocator).toBe('pkg:npm/%40types/node@20.11.5');
  });

  it('generates a minimal SWID tag from structured dependency input', () => {
    const result = generateSwidTag(input);

    expect(result.specVersion).toContain('19770-2');
    expect(result.tag).toContain('<SoftwareIdentity');
    expect(result.tag).toContain('name="my-app"');
    expect(result.tag).toContain('version="1.2.3"');
  });
});

