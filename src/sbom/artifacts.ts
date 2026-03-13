import type { ScanResult, SbomArtifacts } from '../core/types.js';
import { DEFAULT_TOOL_VERSION } from './shared.js';
import { CycloneDxGenerator } from './cyclonedx.js';
import type { CycloneDxSpecVersion } from './cyclonedx.js';
import { SpdxJsonGenerator } from './spdx.js';
import { SwidTagGenerator } from './swid.js';

/** Generates every supported software inventory artifact for a scan. */
export function generateSbomArtifacts(
  scanResult: ScanResult,
  toolVersion: string = DEFAULT_TOOL_VERSION,
  cyclonedxVersion: CycloneDxSpecVersion = '1.7'
): SbomArtifacts {
  // TODO: Make artifact selection configurable instead of always generating all supported formats.
  return {
    cyclonedx: new CycloneDxGenerator(cyclonedxVersion).generate(scanResult, toolVersion),
    spdx: new SpdxJsonGenerator().generate(scanResult, toolVersion),
    swid: new SwidTagGenerator().generate(scanResult, toolVersion),
  };
}

