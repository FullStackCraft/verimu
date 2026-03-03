import { randomUUID } from 'crypto';
import type { SbomGenerator } from './generator.interface.js';
import type { ScanResult, Sbom, SbomFormat } from '../core/types.js';
import {
  DEFAULT_SWID_VERSION,
  DEFAULT_TOOL_VERSION,
  VERIMU_TOOL_NAME,
  extractProjectName,
} from './shared.js';

const SWID_SPEC_VERSION = 'ISO/IEC 19770-2:2015';

/** Generates a minimal SWID XML tag for the root software product. */
export class SwidTagGenerator implements SbomGenerator {
  readonly format: SbomFormat = 'swid-xml';

  generate(scanResult: ScanResult, toolVersion: string = DEFAULT_TOOL_VERSION): Sbom {
    const timestamp = new Date().toISOString();
    const projectName = extractProjectName(scanResult.projectPath);
    const tagId = `com.verimu:${sanitizeTagId(projectName)}:${DEFAULT_SWID_VERSION}:${randomUUID()}`;

    const content = [
      '<?xml version="1.0" encoding="UTF-8"?>',
      '<SoftwareIdentity',
      '  xmlns="http://standards.iso.org/iso/19770/-2/2015/schema.xsd"',
      `  name="${escapeXml(projectName)}"`,
      `  tagId="${escapeXml(tagId)}"`,
      '  tagVersion="1"',
      `  version="${DEFAULT_SWID_VERSION}"`,
      '  versionScheme="semver">',
      `  <Entity name="${escapeXml(projectName)}" role="softwareCreator" />`,
      '  <Entity name="Verimu" role="tagCreator" />',
      `  <Meta product="${escapeXml(projectName)}" generator="${VERIMU_TOOL_NAME}" toolVersion="${toolVersion}" generated="${timestamp}" />`,
      '  <!-- TODO: Consider adding dependency/package evidence if we need richer SWID coverage. -->',
      '  <Link rel="describedby" href="https://verimu.com" />',
      '</SoftwareIdentity>',
    ].join('\n');

    return {
      format: 'swid-xml',
      specVersion: SWID_SPEC_VERSION,
      content,
      componentCount: 1,
      generatedAt: timestamp,
    };
  }
}

function escapeXml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&apos;');
}

function sanitizeTagId(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

