---
created: 2026-02-08 13:38:00
created_by: claude opus 4.5
---

# Verimu npm Scanner + SBOM Pipeline

## What Was Built

Complete TypeScript scanning pipeline that takes an npm project and produces a CycloneDX 1.5 SBOM + CVE vulnerability report. This is repo 2 of 3 in the Verimu architecture (the npm package that runs in CI/CD).

## Architecture

```
package-lock.json → NpmScanner → Dependency[] → CycloneDxGenerator → SBOM (JSON file)
                                              → CveAggregator → OsvSource → Vulnerability[]
                                              → ConsoleReporter → formatted output
```

### Key Interfaces

Every major component is behind an interface for extensibility:

- `DependencyScanner` — implement per ecosystem (npm live, nuget/cargo stubbed)
- `SbomGenerator` — implement per format (CycloneDX live, SPDX stubbed)
- `CveSource` — implement per CVE database (OSV live, NVD/EUVD/CISA-KEV planned)
- `Reporter` — implement per output format (console live, JSON/CRA-report planned)

### File Layout

```
src/
├── core/
│   ├── types.ts          # All shared types (Dependency, Vulnerability, VerimuReport, etc.)
│   └── errors.ts         # Typed error classes (NoLockfileError, LockfileParseError, etc.)
├── scanners/
│   ├── scanner.interface.ts
│   ├── registry.ts       # Auto-detects ecosystem, returns correct scanner
│   ├── npm/npm-scanner.ts       # LIVE — parses package-lock.json v1/v2/v3
│   ├── nuget/nuget-scanner.ts   # STUB
│   └── cargo/cargo-scanner.ts   # STUB
├── sbom/
│   ├── generator.interface.ts
│   └── cyclonedx.ts      # LIVE — CycloneDX 1.5 JSON generation
├── cve/
│   ├── source.interface.ts
│   ├── osv.ts            # LIVE — OSV.dev batch query API
│   └── aggregator.ts     # Merges/deduplicates CVEs from multiple sources
├── reporters/
│   ├── reporter.interface.ts
│   └── console.ts        # LIVE — formatted terminal output
├── scan.ts               # Main pipeline orchestrator
└── index.ts              # Public API exports
```

## npm Scanner Details

Parses `package-lock.json` (supports v1, v2, and v3 formats):
- v2/v3: reads the flat `packages` map (`node_modules/name` → version)
- v1 fallback: recursively walks the nested `dependencies` tree
- Cross-references `package.json` to mark direct vs transitive deps
- Generates purl (Package URL) for each dependency: `pkg:npm/name@version`

## CycloneDX SBOM

Generates spec-compliant CycloneDX 1.5 JSON including:
- `metadata.tools` identifying Verimu as the generator
- `metadata.component` for the root project
- `components[]` with type, name, version, purl, scope (required/optional)
- `dependencies[]` graph (currently flat — full tree reconstruction planned)

## OSV CVE Source

Uses Google's OSV.dev `/v1/querybatch` endpoint:
- Batches up to 1000 packages per request
- Maps OSV ecosystem names (npm → "npm", cargo → "crates.io", etc.)
- Extracts CVE IDs from GHSA aliases (prefers CVE-xxxx as primary ID)
- Parses CVSS v3 scores and maps to severity levels
- Extracts affected version ranges and fix versions from `affected[].ranges`

## CVE Aggregator

Runs multiple CVE sources in parallel via `Promise.allSettled`:
- Deduplicates by `(vuln_id, package_name)` key
- Merges data from multiple sources (strips undefined values to prevent overwrites)
- Preserves best-available data (CVSS score, fix version, affected range)
- Merges `exploitedInWild` flag (true if ANY source reports it)
- Tracks which sources succeeded/failed with error messages

## Test Fixtures

Three fixture projects with realistic package-lock.json files:

| Fixture    | Direct Deps                                  | Total Resolved |
|------------|----------------------------------------------|----------------|
| node-api   | express, lodash, jsonwebtoken, axios, jest   | 12             |
| vue-app    | vue, pinia, vue-router, vite, plugin-vue     | 6              |
| react-app  | react, react-dom, vite, plugin-react         | 5              |

## Test Coverage (33 tests, all passing)

- **npm-scanner.test.ts** (9): lockfile v2/v3 parsing, direct vs transitive, scoped packages, purl generation, missing lockfile error
- **cyclonedx.test.ts** (6): valid SBOM structure, component mapping, dependency graph, metadata, purl encoding
- **osv.test.ts** (7): batch query format, vuln mapping, CVE ID extraction, aliases, severity parsing, error handling
- **aggregator.test.ts** (5): multi-source merge, deduplication, source failures, duration tracking, exploitedInWild merge
- **pipeline.test.ts** (6): end-to-end scan, SBOM file output, shouldFailCi threshold, console report formatting

## Bugs Fixed

1. **Aggregator dedup spread bug**: `{ ...a, ...b }` was letting `undefined` values from one source overwrite real values from another. Fixed by stripping undefined/null before spreading.
2. **OSV aliases missing original ID**: When promoting a CVE ID from aliases to the main `id` field, the original GHSA ID wasn't being included in the `aliases` array. Fixed by merging `[osvVuln.id, ...osvVuln.aliases]`.

## What's Next

- [ ] CLI entry point (`verimu scan .`)
- [ ] GitHub Action wrapper (`action.yml`)
- [ ] Snapshot upload to backend API (POST /v1/snapshots)
- [ ] NVD + GitHub Advisory CVE sources
- [ ] NuGet and Cargo scanner implementations
- [ ] SPDX SBOM format support

## Update: CycloneDX 1.7 + NTIA Supplier Compliance (2026-02-08)

### Changes
- Upgraded CycloneDX spec from **1.5 → 1.7** (latest, released Oct 2025)
- Schema URL updated to `bom-1.7.schema.json`
- Added **supplier fields** to pass NTIA SBOM minimum elements validation

### NTIA Supplier Strategy

The NTIA (National Telecommunications and Information Administration) requires `supplier` on both metadata and every component. Since npm lockfiles don't contain author/publisher metadata, we use this heuristic:

| Field | Value | Rationale |
|-------|-------|-----------|
| `metadata.supplier.name` | Project directory name | The org supplying the root software |
| `metadata.component.supplier.name` | Project directory name | Same as above |
| `metadata.tools[].supplier.name` | `"Verimu"` | The tool generating the SBOM |
| `components[].supplier.name` | Package scope or name | `@vue/reactivity` → `@vue`, `express` → `express` |

This matches the approach used by Syft, Trivy, and other production SBOM tools when registry metadata isn't available from lockfile parsing.

### Future Enhancement
When the backend is built, we could enrich supplier data by querying the npm registry API for `maintainers` and `author` fields during snapshot processing — providing more accurate supplier names without slowing down the CI scan.

### Test Coverage
Added 4 NTIA-specific tests (37 total, all passing):
- `metadata.supplier` present
- `component.supplier` on ALL components
- Scoped packages use npm scope as supplier
- Tool component has Verimu supplier

## Update: PURL Encoding + Single Root Node Fix (2026-02-08)

### Issue 1: Invalid PURL for scoped npm packages
**Problem:** Scoped packages like `@types/node` were generating `pkg:npm/@types%2Fnode@20.11.5` — encoding the `/` as `%2F`. The NTIA validator rejected this as an invalid identifier.

**Root cause:** Code did `name.replace('/', '%2F')` — but the purl spec uses `/` as the namespace separator. For scoped npm packages, the scope IS the namespace, so the `/` between scope and name must stay unencoded.

**Fix:** Removed the `replace('/', '%2F')` call entirely. Now generates `pkg:npm/@types/node@20.11.5` per the [purl spec examples](https://github.com/package-url/purl-spec/blob/main/types-doc/npm-definition.md).

### Issue 2: Multiple root nodes in dependency graph
**Problem:** NTIA validator reported "Found 8 root components, only one expected." Every dependency had a `{ ref: "pkg:npm/...", dependsOn: [] }` entry — transitive deps that nothing pointed to were treated as additional root nodes.

**Root cause:** We emitted a dependency entry for every package, even those with empty `dependsOn: []`. In graph theory, any node with no inbound edges is a root.

**Fix:** Only emit a single dependency entry: the root component, which `dependsOn` ALL dependencies (direct + transitive). Since we parse a flat lockfile and can't reliably reconstruct which transitive belongs to which direct dep, a flat-but-complete graph is the correct representation. This is valid per CycloneDX spec and matches how tools like Syft handle flat lockfiles.

### Validation Status
Both fixes confirmed by regenerating the SBOM and checking:
- All purls are unencoded (no `%2F`)
- Dependency graph has exactly 1 entry, 1 root node
- 37 tests passing
