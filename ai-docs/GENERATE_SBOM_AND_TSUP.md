---
created: 2026-02-08 15:45:00
created_by: claude opus 4.5
---

# generateSbom() + tsup Dual Build

## Summary
Added `generateSbom()` as a first-class pure function export, switched build tooling from `tsc` to `tsup` for dual ESM/CJS output, and bumped version to 0.0.1.

## New: `generateSbom()`

### File
`src/generate-sbom.ts`

### Purpose
Pure function — no filesystem, no network, no side effects. Takes structured dependency data, returns an NTIA-compliant CycloneDX 1.7 SBOM. Works in Node.js, Deno, Bun, and browsers (via the verimu.com try-it page).

### Signature
```ts
generateSbom(input: GenerateSbomInput): GenerateSbomResult
```

### Input
```ts
interface GenerateSbomInput {
  projectName: string;
  projectVersion?: string;       // defaults to "0.0.0"
  dependencies: SbomDependency[];
}

interface SbomDependency {
  name: string;
  version: string;
  ecosystem: Ecosystem;          // 'npm' | 'nuget' | 'cargo' | 'maven' | 'pip' | 'go'
  direct?: boolean;              // defaults to true
  purl?: string;                 // auto-generated if omitted
}
```

### Output
```ts
interface GenerateSbomResult {
  sbom: Record<string, unknown>;  // parsed JS object
  content: string;                // formatted JSON string
  componentCount: number;
  specVersion: string;            // "1.7"
  generatedAt: string;            // ISO timestamp
}
```

### Key behaviors
- PURLs auto-generated per purl-spec (scoped npm: `%40` encoding)
- Supplier derived from scope (`@vue/reactivity` → `@vue`) or package name
- Single-root dependency graph (flat, all deps under root)
- `urn:uuid:` serial number via `crypto.randomUUID()`
- Ecosystem-aware PURL types: npm→npm, nuget→nuget, cargo→cargo, pip→pypi, go→golang

## Top-level API

```ts
import { scan, generateSbom, shouldFailCi } from 'verimu'
```

- `scan(config)` — full CI/CD pipeline (filesystem + network)
- `generateSbom(input)` — pure SBOM generation
- `shouldFailCi(report, threshold)` — severity gate

## Build: tsup

### Config
`tsup.config.ts` — entry `src/index.ts`, formats `['esm', 'cjs']`, target `node20`

### Output
```
dist/index.mjs      — ESM
dist/index.cjs      — CJS
dist/index.d.ts     — ESM types
dist/index.d.cts    — CJS types
dist/index.mjs.map  — sourcemap
dist/index.cjs.map  — sourcemap
```

### package.json exports
```json
{
  "exports": {
    ".": {
      "import":  { "types": "./dist/index.d.ts",  "default": "./dist/index.mjs" },
      "require": { "types": "./dist/index.d.cts", "default": "./dist/index.cjs" }
    }
  }
}
```

## Tests
15 new tests in `test/unit/generate-sbom.test.ts` — covers PURL encoding, scoped packages, supplier derivation, scope marking, multi-ecosystem, empty deps, custom PURLs.

Total: 52 tests across 6 files, all passing.
