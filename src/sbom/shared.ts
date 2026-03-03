import type { Ecosystem } from '../core/types.js';

export const VERIMU_TOOL_NAME = 'verimu';
export const VERIMU_TOOL_WEBSITE = 'https://verimu.com';
export const VERIMU_TOOL_DESCRIPTION = 'Verimu CRA Compliance Scanner';
export const DEFAULT_TOOL_VERSION = '0.1.0';
export const DEFAULT_PROJECT_VERSION = '0.0.0';
export const DEFAULT_SWID_VERSION = '0.0.0';

type DependencyLike = {
  name: string;
  version: string;
  ecosystem: Ecosystem;
  direct?: boolean;
  purl?: string;
};

export interface NormalizedDependency {
  name: string;
  version: string;
  ecosystem: Ecosystem;
  direct: boolean;
  purl: string;
  supplierName: string;
}

const PURL_TYPE_MAP: Record<Ecosystem, string> = {
  npm: 'npm',
  nuget: 'nuget',
  cargo: 'cargo',
  maven: 'maven',
  pip: 'pypi',
  poetry: 'pypi',
  uv: 'pypi',
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
 */
export function buildPurl(name: string, version: string, ecosystem: Ecosystem): string {
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
export function deriveSupplierName(packageName: string): string {
  if (packageName.startsWith('@')) {
    return packageName.split('/')[0];
  }
  return packageName;
}

/** Extracts project name from a file system path */
export function extractProjectName(projectPath: string): string {
  const parts = projectPath.replace(/\\/g, '/').split('/');
  return parts[parts.length - 1] || 'unknown-project';
}

/** Normalizes dependencies so all generators work from the same shape */
export function normalizeDependencies(dependencies: DependencyLike[]): NormalizedDependency[] {
  return dependencies.map((dep) => ({
    name: dep.name,
    version: dep.version,
    ecosystem: dep.ecosystem,
    direct: dep.direct ?? true,
    purl: dep.purl ?? buildPurl(dep.name, dep.version, dep.ecosystem),
    supplierName: deriveSupplierName(dep.name),
  }));
}

