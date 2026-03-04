import { describe, it, expect } from 'vitest';
import { GoScanner } from '../../src/scanners/go/go-scanner.js';
import path from 'path';

const FIXTURES = path.resolve(__dirname, '../fixtures');

describe('GoScanner', () => {
  const scanner = new GoScanner();

  describe('detect()', () => {
    it('finds go.sum in a Go project', async () => {
      const result = await scanner.detect(path.join(FIXTURES, 'go-api'));
      expect(result).not.toBeNull();
      expect(result).toContain('go.sum');
    });

    it('returns null for a project with no go.sum', async () => {
      const result = await scanner.detect(path.join(FIXTURES, 'empty-project'));
      expect(result).toBeNull();
    });

    it('returns null for an npm project', async () => {
      const result = await scanner.detect(path.join(FIXTURES, 'node-api'));
      expect(result).toBeNull();
    });
  });

  describe('scan() — go-api fixture (synthetic)', () => {
    it('parses all dependencies from go.sum', async () => {
      const lockfilePath = path.join(FIXTURES, 'go-api', 'go.sum');
      const result = await scanner.scan(path.join(FIXTURES, 'go-api'), lockfilePath);

      expect(result.ecosystem).toBe('go');
      // 9 modules in go.sum (deduplicated, /go.mod lines skipped)
      expect(result.dependencies.length).toBe(9);
    });

    it('skips /go.mod checksum lines (deduplicates)', async () => {
      const lockfilePath = path.join(FIXTURES, 'go-api', 'go.sum');
      const result = await scanner.scan(path.join(FIXTURES, 'go-api'), lockfilePath);

      // Each module should appear only once despite having h1: and /go.mod lines
      const ginCount = result.dependencies.filter((d) => d.name === 'github.com/gin-gonic/gin').length;
      expect(ginCount).toBe(1);
    });

    it('correctly identifies direct vs indirect dependencies from go.mod', async () => {
      const lockfilePath = path.join(FIXTURES, 'go-api', 'go.sum');
      const result = await scanner.scan(path.join(FIXTURES, 'go-api'), lockfilePath);

      // Direct deps from go.mod (no // indirect comment)
      const directDeps = result.dependencies.filter((d) => d.direct);
      const directNames = directDeps.map((d) => d.name).sort();
      expect(directNames).toContain('github.com/gin-gonic/gin');
      expect(directNames).toContain('github.com/lib/pq');
      expect(directNames).toContain('go.uber.org/zap');

      // Indirect deps (marked // indirect in go.mod)
      const indirectDeps = result.dependencies.filter((d) => !d.direct);
      const indirectNames = indirectDeps.map((d) => d.name).sort();
      expect(indirectNames).toContain('github.com/bytedance/sonic');
      expect(indirectNames).toContain('github.com/go-playground/validator/v10');
      expect(indirectNames).toContain('github.com/pelletier/go-toml/v2');
      expect(indirectNames).toContain('go.uber.org/multierr');
      expect(indirectNames).toContain('golang.org/x/net');
      expect(indirectNames).toContain('golang.org/x/sys');
    });

    it('generates correct Go purls', async () => {
      const lockfilePath = path.join(FIXTURES, 'go-api', 'go.sum');
      const result = await scanner.scan(path.join(FIXTURES, 'go-api'), lockfilePath);

      const gin = result.dependencies.find((d) => d.name === 'github.com/gin-gonic/gin');
      expect(gin?.purl).toBe('pkg:golang/github.com/gin-gonic/gin@v1.9.1');

      const zap = result.dependencies.find((d) => d.name === 'go.uber.org/zap');
      expect(zap?.purl).toBe('pkg:golang/go.uber.org/zap@v1.26.0');
    });

    it('handles versioned module paths (v10, v2)', async () => {
      const lockfilePath = path.join(FIXTURES, 'go-api', 'go.sum');
      const result = await scanner.scan(path.join(FIXTURES, 'go-api'), lockfilePath);

      const validator = result.dependencies.find((d) =>
        d.name === 'github.com/go-playground/validator/v10'
      );
      expect(validator).toBeDefined();
      expect(validator?.version).toBe('v10.16.0');
      expect(validator?.purl).toBe(
        'pkg:golang/github.com/go-playground/validator/v10@v10.16.0'
      );
    });

    it('sets ecosystem to go for all dependencies', async () => {
      const lockfilePath = path.join(FIXTURES, 'go-api', 'go.sum');
      const result = await scanner.scan(path.join(FIXTURES, 'go-api'), lockfilePath);

      expect(result.dependencies.every((d) => d.ecosystem === 'go')).toBe(true);
    });

    it('sets scannedAt timestamp', async () => {
      const lockfilePath = path.join(FIXTURES, 'go-api', 'go.sum');
      const result = await scanner.scan(path.join(FIXTURES, 'go-api'), lockfilePath);
      expect(result.scannedAt).toBeTruthy();
      expect(new Date(result.scannedAt).getTime()).not.toBeNaN();
    });
  });

  describe('scan() — go-service fixture (real-world)', () => {
    it('parses a realistic Go microservice project', async () => {
      const lockfilePath = path.join(FIXTURES, 'go-service', 'go.sum');
      const result = await scanner.scan(path.join(FIXTURES, 'go-service'), lockfilePath);

      expect(result.ecosystem).toBe('go');
      expect(result.dependencies.length).toBe(22);
    });

    it('identifies direct dependencies from go.mod', async () => {
      const lockfilePath = path.join(FIXTURES, 'go-service', 'go.sum');
      const result = await scanner.scan(path.join(FIXTURES, 'go-service'), lockfilePath);

      const directDeps = result.dependencies.filter((d) => d.direct);
      const directNames = directDeps.map((d) => d.name).sort();

      expect(directNames).toContain('github.com/go-chi/chi/v5');
      expect(directNames).toContain('github.com/go-chi/cors');
      expect(directNames).toContain('github.com/google/uuid');
      expect(directNames).toContain('github.com/jackc/pgx/v5');
      expect(directNames).toContain('github.com/redis/go-redis/v9');
      expect(directNames).toContain('github.com/rs/zerolog');
      expect(directNames).toContain('github.com/golang-jwt/jwt/v5');
      expect(directNames).toContain('google.golang.org/grpc');
      expect(directNames).toContain('google.golang.org/protobuf');
    });

    it('includes indirect dependencies (pgx internals, stdlib)', async () => {
      const lockfilePath = path.join(FIXTURES, 'go-service', 'go.sum');
      const result = await scanner.scan(path.join(FIXTURES, 'go-service'), lockfilePath);

      const indirectNames = result.dependencies
        .filter((d) => !d.direct)
        .map((d) => d.name);

      expect(indirectNames).toContain('github.com/jackc/pgpassfile');
      expect(indirectNames).toContain('github.com/jackc/pgservicefile');
      expect(indirectNames).toContain('github.com/jackc/puddle/v2');
      expect(indirectNames).toContain('golang.org/x/crypto');
      expect(indirectNames).toContain('golang.org/x/text');
      expect(indirectNames).toContain('google.golang.org/genproto/googleapis/rpc');
    });

    it('generates correct purls for google.golang.org modules', async () => {
      const lockfilePath = path.join(FIXTURES, 'go-service', 'go.sum');
      const result = await scanner.scan(path.join(FIXTURES, 'go-service'), lockfilePath);

      const grpc = result.dependencies.find((d) => d.name === 'google.golang.org/grpc');
      expect(grpc?.purl).toBe('pkg:golang/google.golang.org/grpc@v1.61.0');

      const protobuf = result.dependencies.find((d) => d.name === 'google.golang.org/protobuf');
      expect(protobuf?.purl).toBe('pkg:golang/google.golang.org/protobuf@v1.32.0');
    });

    it('handles pseudo-versions correctly', async () => {
      const lockfilePath = path.join(FIXTURES, 'go-service', 'go.sum');
      const result = await scanner.scan(path.join(FIXTURES, 'go-service'), lockfilePath);

      // dgryski/go-rendezvous has a pseudo-version
      const rendezvous = result.dependencies.find((d) =>
        d.name === 'github.com/dgryski/go-rendezvous'
      );
      expect(rendezvous).toBeDefined();
      expect(rendezvous?.version).toBe('v0.0.0-20200823014737-9f7001d12a5f');
    });
  });
});
