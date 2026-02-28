import type { ScanResult, SbomArtifacts } from '../core/types.js';
import { DEFAULT_TOOL_VERSION } from './shared.js';
import { CycloneDxGenerator } from './cyclonedx.js';
import { SpdxJsonGenerator } from './spdx.js';
import { SwidTagGenerator } from './swid.js';

/** Generates every supported software inventory artifact for a scan. */
export function generateSbomArtifacts(
  scanResult: ScanResult,
  toolVersion: string = DEFAULT_TOOL_VERSION
): SbomArtifacts {
  // TODO: Make artifact selection configurable instead of always generating all supported formats.
  return {
    cyclonedx: new CycloneDxGenerator().generate(scanResult, toolVersion),
    spdx: new SpdxJsonGenerator().generate(scanResult, toolVersion),
    swid: new SwidTagGenerator().generate(scanResult, toolVersion),
  };
}

