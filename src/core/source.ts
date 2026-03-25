/**
 * Source detection for SBOM scans.
 *
 * Determines the scan source with the following priority:
 *   1. VERIMU_SOURCE environment variable (explicit override)
 *   2. Auto-detect CI/CD environment
 *   3. Default to "cli"
 */

export type SbomSource = 'cli' | 'cicd';

/** CI environment variable signatures used for auto-detection */
const CI_ENV_SIGNATURES: Record<string, string> = {
  // Generic CI marker (most CI systems set this)
  CI: 'true',
  // GitHub Actions
  GITHUB_ACTIONS: 'true',
  // GitLab CI
  GITLAB_CI: 'true',
  // Bitbucket Pipelines
  BITBUCKET_BUILD_NUMBER: '*',
  // CircleCI
  CIRCLECI: 'true',
  // Jenkins
  JENKINS_URL: '*',
  // Azure Pipelines
  TF_BUILD: 'True',
  // Travis CI
  TRAVIS: 'true',
  // TeamCity
  TEAMCITY_VERSION: '*',
  // AWS CodeBuild
  CODEBUILD_BUILD_ID: '*',
  // Drone CI
  DRONE: 'true',
  // Buildkite
  BUILDKITE: 'true',
  // Vercel
  VERCEL: '1',
  // Netlify
  NETLIFY: 'true',
  // Heroku CI
  HEROKU_TEST_RUN_ID: '*',
  // Semaphore CI
  SEMAPHORE: 'true',
  // AppVeyor
  APPVEYOR: 'True',
  // Woodpecker CI
  CI_PIPELINE_ID: '*',
};

/**
 * Detects if the current environment is a CI/CD system.
 * Returns true if any known CI environment variable is set.
 */
function isInCiEnvironment(): boolean {
  for (const [envVar, expectedValue] of Object.entries(CI_ENV_SIGNATURES)) {
    const actualValue = process.env[envVar];
    if (actualValue === undefined || actualValue === '') {
      continue;
    }
    if (expectedValue === '*' || actualValue.toLowerCase() === expectedValue.toLowerCase()) {
      return true;
    }
  }
  return false;
}

/**
 * Detects the scan source with priority:
 *   1. VERIMU_SOURCE env var (explicit override)
 *   2. Auto-detect CI/CD environment
 *   3. Default to "cli"
 */
export function detectSource(): SbomSource {
  // 1. Check explicit env var override
  const explicitSource = process.env.VERIMU_SOURCE?.trim().toLowerCase();
  if (explicitSource) {
    if (explicitSource === 'cicd' || explicitSource === 'ci/cd' || explicitSource === 'ci') {
      return 'cicd';
    }
    // Any other value (including 'cli') defaults to CLI
    return 'cli';
  }

  // 2. Auto-detect CI/CD environment
  if (isInCiEnvironment()) {
    return 'cicd';
  }

  // 3. Default to CLI
  return 'cli';
}
