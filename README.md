# verimu

The NPM package for `verimu`, a tool for producing CRA-compliant SBOMs via CI / CD pipelines.

## Documentation and Website

[https://verimu.com](https://verimu.com)

## Supported CI / CD Platforms

The core scanning pipeline is CI-agnostic — it works in any environment with Node.js 20+.
Example CI configs are provided in the `ci-examples/` directory.

- [x] GitHub Actions (`.github/workflows/ci.yml`, `.github/workflows/publish-npm.yml`)
- [x] GitLab CI (`ci-examples/gitlab-ci.yml`)
- [x] Bitbucket Pipelines (`ci-examples/bitbucket-pipelines.yml`)

## Supported Package Ecosystems

- [x] npm (package-lock.json)
- [x] yarn (yarn.lock)
- [x] pnpm (pnpm-lock.yaml)
- [x] NuGet (packages.lock.json)
- [x] pip (requirements.txt, Pipfile.lock)
- [x] Cargo (Cargo.lock)
- [x] Maven (pom.xml + dependency-tree.txt or `mvn` on PATH)
- [x] Go (go.sum)
- [x] Ruby (Gemfile.lock)
- [x] Composer (composer.lock)

## Development

To run the tests, use:

```bash
npm test
```

## Releasing to npm (Tag Pipelines)

`verimu` can publish from GitHub Actions, GitLab CI, and Bitbucket Pipelines when a semver tag is pushed.
Each pipeline validates:

- tag is semver (i.e. `1.2.3` without a `v` prefix)
- tag version must match `package.json` version
- tagged commit exists on `main`

### Publish credentials

- GitHub Actions (`.github/workflows/publish-npm.yml`): uses npm Trusted Publishing (OIDC), so NO `NPM_TOKEN` secret is required.
- GitLab and Bitbucket pipelines in this repo still use `NPM_TOKEN` (`.gitlab-ci.yml`, `bitbucket-pipelines.yml`).

### Recommended release flow

1. Bump version on `main` with npm (this updates `package.json` and `package-lock.json`, then creates a git tag):

```bash
npm version patch
```

2. Push commit and tag:

```bash
git push origin main --follow-tags
```

3. Your CI provider runs the publish job on that tag and releases to npm.

### Why this avoids version conflicts

The source of truth remains the version committed on `main`.
The tag is only a release trigger for that exact versioned commit.
You should not tag arbitrary commits with a new version string that is not already committed in `package.json`.

## Maven Scanner Notes

The Maven scanner needs resolved dependencies. Since Maven has no lockfile, it uses two strategies:

1. **Pre-generated dependency tree** (recommended for CI): Run `mvn dependency:list -DoutputFile=dependency-tree.txt -DappendOutput=true` before scanning.
2. **Auto-detect**: If `mvn` is on `$PATH`, the scanner runs `mvn dependency:list` automatically.

## Three CI / CD Pipelines as Self Check on the `verimu` package itself

There is a `bitbucket-pipelines.yml` and `.gitlab-ci.yml` in the root of the project, as well as a `.github/workflows/ci.yml` file, all of which run `verimu` against itself in each of the 3 frameworks we support (GitHub Actions, GitLab CI, Bitbucket Pipelines). The tests should pass in all 3 environments, confirming that `verimu` can successfully scan its own dependencies and produce a report.

Tag-based npm release automation in GitHub Actions is handled by `.github/workflows/publish-npm.yml`, so this repo remains a working cross-provider reference for both scanning and publishing.
