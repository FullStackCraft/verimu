import { describe, it, expect } from 'vitest';
import { CargoScanner } from '../../src/scanners/cargo/cargo-scanner.js';
import path from 'path';

const FIXTURES = path.resolve(__dirname, '../fixtures');

describe('CargoScanner', () => {
  const scanner = new CargoScanner();

  describe('detect()', () => {
    it('finds Cargo.lock in a Rust project', async () => {
      const result = await scanner.detect(path.join(FIXTURES, 'rust-cli'));
      expect(result).not.toBeNull();
      expect(result).toContain('Cargo.lock');
    });

    it('returns null for a project with no Cargo.lock', async () => {
      const result = await scanner.detect(path.join(FIXTURES, 'empty-project'));
      expect(result).toBeNull();
    });

    it('returns null for an npm project', async () => {
      const result = await scanner.detect(path.join(FIXTURES, 'node-api'));
      expect(result).toBeNull();
    });
  });

  describe('scan() — rust-cli fixture (synthetic)', () => {
    it('parses all dependencies from Cargo.lock', async () => {
      const lockfilePath = path.join(FIXTURES, 'rust-cli', 'Cargo.lock');
      const result = await scanner.scan(path.join(FIXTURES, 'rust-cli'), lockfilePath);

      expect(result.ecosystem).toBe('cargo');
      // 8 packages in lock file minus 1 root = 7 deps
      expect(result.dependencies.length).toBe(8);
    });

    it('skips the root project package', async () => {
      const lockfilePath = path.join(FIXTURES, 'rust-cli', 'Cargo.lock');
      const result = await scanner.scan(path.join(FIXTURES, 'rust-cli'), lockfilePath);

      const rootPkg = result.dependencies.find((d) => d.name === 'acme-cli');
      expect(rootPkg).toBeUndefined();
    });

    it('correctly identifies direct vs transitive dependencies', async () => {
      const lockfilePath = path.join(FIXTURES, 'rust-cli', 'Cargo.lock');
      const result = await scanner.scan(path.join(FIXTURES, 'rust-cli'), lockfilePath);

      const directDeps = result.dependencies.filter((d) => d.direct);
      const directNames = directDeps.map((d) => d.name).sort();
      expect(directNames).toContain('clap');
      expect(directNames).toContain('serde');
      expect(directNames).toContain('serde_json');
      expect(directNames).toContain('tokio');
      expect(directNames).toContain('reqwest');

      // clap_builder and serde_derive are transitive
      const transitiveDeps = result.dependencies.filter((d) => !d.direct);
      const transitiveNames = transitiveDeps.map((d) => d.name).sort();
      expect(transitiveNames).toContain('clap_builder');
      expect(transitiveNames).toContain('serde_derive');
    });

    it('generates correct Cargo purls', async () => {
      const lockfilePath = path.join(FIXTURES, 'rust-cli', 'Cargo.lock');
      const result = await scanner.scan(path.join(FIXTURES, 'rust-cli'), lockfilePath);

      const serde = result.dependencies.find((d) => d.name === 'serde');
      expect(serde?.purl).toBe('pkg:cargo/serde@1.0.195');

      const tokio = result.dependencies.find((d) => d.name === 'tokio');
      expect(tokio?.purl).toBe('pkg:cargo/tokio@1.35.1');
    });

    it('sets ecosystem to cargo for all dependencies', async () => {
      const lockfilePath = path.join(FIXTURES, 'rust-cli', 'Cargo.lock');
      const result = await scanner.scan(path.join(FIXTURES, 'rust-cli'), lockfilePath);

      expect(result.dependencies.every((d) => d.ecosystem === 'cargo')).toBe(true);
    });

    it('sets scannedAt timestamp', async () => {
      const lockfilePath = path.join(FIXTURES, 'rust-cli', 'Cargo.lock');
      const result = await scanner.scan(path.join(FIXTURES, 'rust-cli'), lockfilePath);
      expect(result.scannedAt).toBeTruthy();
      expect(new Date(result.scannedAt).getTime()).not.toBeNaN();
    });
  });

  describe('scan() — rust-webserver fixture (real-world)', () => {
    it('parses a realistic Actix-web project', async () => {
      const lockfilePath = path.join(FIXTURES, 'rust-webserver', 'Cargo.lock');
      const result = await scanner.scan(path.join(FIXTURES, 'rust-webserver'), lockfilePath);

      expect(result.ecosystem).toBe('cargo');
      // 15 packages minus 1 root = 14 deps
      expect(result.dependencies.length).toBe(14);
    });

    it('identifies direct dependencies from Cargo.toml', async () => {
      const lockfilePath = path.join(FIXTURES, 'rust-webserver', 'Cargo.lock');
      const result = await scanner.scan(path.join(FIXTURES, 'rust-webserver'), lockfilePath);

      const directDeps = result.dependencies.filter((d) => d.direct);
      const directNames = directDeps.map((d) => d.name).sort();

      expect(directNames).toContain('actix-web');
      expect(directNames).toContain('serde');
      expect(directNames).toContain('serde_json');
      expect(directNames).toContain('tokio');
      expect(directNames).toContain('sqlx');
      expect(directNames).toContain('tracing');
      expect(directNames).toContain('tracing-subscriber');
    });

    it('includes transitive dependencies (actix-http, sqlx-core)', async () => {
      const lockfilePath = path.join(FIXTURES, 'rust-webserver', 'Cargo.lock');
      const result = await scanner.scan(path.join(FIXTURES, 'rust-webserver'), lockfilePath);

      const names = result.dependencies.map((d) => d.name);
      expect(names).toContain('actix-http');
      expect(names).toContain('actix-router');
      expect(names).toContain('sqlx-core');
      expect(names).toContain('sqlx-postgres');
      expect(names).toContain('tracing-core');
    });
  });
});
