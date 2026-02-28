import { randomUUID } from 'crypto';
import type {
  GenerateSbomInput,
  GenerateSwidTagResult,
} from './core/types.js';
import {
  DEFAULT_PROJECT_VERSION,
  DEFAULT_SWID_VERSION,
  VERIMU_TOOL_NAME,
} from './sbom/shared.js';

const SWID_SPEC_VERSION = 'ISO/IEC 19770-2:2015';

/**
 * Generates a minimal SWID XML tag for the root software product.
 *
 * This is intentionally minimal for v1. The current tag describes the root
 * product identity and generator metadata only.
 */
export function generateSwidTag(input: GenerateSbomInput): GenerateSwidTagResult {
  const {
    projectName,
    projectVersion = DEFAULT_PROJECT_VERSION,
  } = input;

  const timestamp = new Date().toISOString();
  const tagVersion = 1;
  const normalizedVersion = projectVersion || DEFAULT_SWID_VERSION;
  const tagId = `com.verimu:${sanitizeTagId(projectName)}:${normalizedVersion}:${randomUUID()}`;

  const tag = [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<SoftwareIdentity',
    '  xmlns="http://standards.iso.org/iso/19770/-2/2015/schema.xsd"',
    `  name="${escapeXml(projectName)}"`,
    `  tagId="${escapeXml(tagId)}"`,
    `  tagVersion="${tagVersion}"`,
    `  version="${escapeXml(normalizedVersion)}"`,
    '  versionScheme="semver">',
    `  <Entity name="${escapeXml(projectName)}" role="softwareCreator" />`,
    '  <Entity name="Verimu" role="tagCreator" />',
    `  <Meta product="${escapeXml(projectName)}" generator="${VERIMU_TOOL_NAME}" generated="${timestamp}" />`,
    '  <!-- TODO: Consider adding dependency/package evidence if we need richer SWID coverage. -->',
    '  <Link rel="describedby" href="https://verimu.com" />',
    '</SoftwareIdentity>',
  ].join('\n');

  return {
    tag,
    content: tag,
    componentCount: 1,
    specVersion: SWID_SPEC_VERSION,
    generatedAt: timestamp,
  };
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

