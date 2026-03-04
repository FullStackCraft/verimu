import { describe, it, expect } from 'vitest';
import { RubyScanner } from '../../src/scanners/ruby/ruby-scanner.js';
import path from 'path';

const FIXTURES = path.resolve(__dirname, '../fixtures');

describe('RubyScanner', () => {
  const scanner = new RubyScanner();

  describe('detect()', () => {
    it('finds Gemfile.lock in a Ruby project', async () => {
      const result = await scanner.detect(path.join(FIXTURES, 'ruby-api'));
      expect(result).not.toBeNull();
      expect(result).toContain('Gemfile.lock');
    });

    it('returns null for a project with no Gemfile.lock', async () => {
      const result = await scanner.detect(path.join(FIXTURES, 'empty-project'));
      expect(result).toBeNull();
    });

    it('returns null for an npm project', async () => {
      const result = await scanner.detect(path.join(FIXTURES, 'node-api'));
      expect(result).toBeNull();
    });
  });

  describe('scan() — ruby-api fixture (synthetic)', () => {
    it('parses all gems from the specs section', async () => {
      const lockfilePath = path.join(FIXTURES, 'ruby-api', 'Gemfile.lock');
      const result = await scanner.scan(path.join(FIXTURES, 'ruby-api'), lockfilePath);

      expect(result.ecosystem).toBe('ruby');
      // 10 gems in specs: base64, mustermann, nio4r, pg, puma, rack,
      // rack-protection, ruby2_keywords, sinatra, tilt
      expect(result.dependencies.length).toBe(10);
    });

    it('correctly identifies direct vs transitive dependencies', async () => {
      const lockfilePath = path.join(FIXTURES, 'ruby-api', 'Gemfile.lock');
      const result = await scanner.scan(path.join(FIXTURES, 'ruby-api'), lockfilePath);

      // Direct deps from DEPENDENCIES: pg, puma, sinatra
      const directDeps = result.dependencies.filter((d) => d.direct);
      const directNames = directDeps.map((d) => d.name).sort();
      expect(directNames).toEqual(['pg', 'puma', 'sinatra']);

      // Transitive deps
      const transitiveDeps = result.dependencies.filter((d) => !d.direct);
      const transitiveNames = transitiveDeps.map((d) => d.name).sort();
      expect(transitiveNames).toContain('rack');
      expect(transitiveNames).toContain('nio4r');
      expect(transitiveNames).toContain('mustermann');
      expect(transitiveNames).toContain('tilt');
      expect(transitiveNames).toContain('base64');
      expect(transitiveNames).toContain('rack-protection');
      expect(transitiveNames).toContain('ruby2_keywords');
    });

    it('generates correct gem purls', async () => {
      const lockfilePath = path.join(FIXTURES, 'ruby-api', 'Gemfile.lock');
      const result = await scanner.scan(path.join(FIXTURES, 'ruby-api'), lockfilePath);

      const sinatra = result.dependencies.find((d) => d.name === 'sinatra');
      expect(sinatra?.purl).toBe('pkg:gem/sinatra@4.0.0');

      const puma = result.dependencies.find((d) => d.name === 'puma');
      expect(puma?.purl).toBe('pkg:gem/puma@6.4.2');

      const rack = result.dependencies.find((d) => d.name === 'rack');
      expect(rack?.purl).toBe('pkg:gem/rack@3.0.8');
    });

    it('extracts correct versions', async () => {
      const lockfilePath = path.join(FIXTURES, 'ruby-api', 'Gemfile.lock');
      const result = await scanner.scan(path.join(FIXTURES, 'ruby-api'), lockfilePath);

      const pg = result.dependencies.find((d) => d.name === 'pg');
      expect(pg?.version).toBe('1.5.4');

      const nio4r = result.dependencies.find((d) => d.name === 'nio4r');
      expect(nio4r?.version).toBe('2.7.0');
    });

    it('sets ecosystem to ruby for all dependencies', async () => {
      const lockfilePath = path.join(FIXTURES, 'ruby-api', 'Gemfile.lock');
      const result = await scanner.scan(path.join(FIXTURES, 'ruby-api'), lockfilePath);

      expect(result.dependencies.every((d) => d.ecosystem === 'ruby')).toBe(true);
    });

    it('sets scannedAt timestamp', async () => {
      const lockfilePath = path.join(FIXTURES, 'ruby-api', 'Gemfile.lock');
      const result = await scanner.scan(path.join(FIXTURES, 'ruby-api'), lockfilePath);
      expect(result.scannedAt).toBeTruthy();
      expect(new Date(result.scannedAt).getTime()).not.toBeNaN();
    });
  });

  describe('scan() — ruby-service fixture (real-world)', () => {
    it('parses a realistic Rails-like project', async () => {
      const lockfilePath = path.join(FIXTURES, 'ruby-service', 'Gemfile.lock');
      const result = await scanner.scan(path.join(FIXTURES, 'ruby-service'), lockfilePath);

      expect(result.ecosystem).toBe('ruby');
      // 40 gems in specs section
      expect(result.dependencies.length).toBe(40);
    });

    it('identifies direct dependencies from DEPENDENCIES section', async () => {
      const lockfilePath = path.join(FIXTURES, 'ruby-service', 'Gemfile.lock');
      const result = await scanner.scan(path.join(FIXTURES, 'ruby-service'), lockfilePath);

      const directDeps = result.dependencies.filter((d) => d.direct);
      const directNames = directDeps.map((d) => d.name).sort();

      expect(directNames).toContain('bootsnap');
      expect(directNames).toContain('devise');
      expect(directNames).toContain('nokogiri');
      expect(directNames).toContain('pg');
      expect(directNames).toContain('puma');
      expect(directNames).toContain('railties');
      expect(directNames).toContain('redis');
      expect(directNames).toContain('sidekiq');
    });

    it('includes transitive Rails framework gems', async () => {
      const lockfilePath = path.join(FIXTURES, 'ruby-service', 'Gemfile.lock');
      const result = await scanner.scan(path.join(FIXTURES, 'ruby-service'), lockfilePath);

      const transitiveNames = result.dependencies
        .filter((d) => !d.direct)
        .map((d) => d.name);

      expect(transitiveNames).toContain('actioncable');
      expect(transitiveNames).toContain('actionpack');
      expect(transitiveNames).toContain('activesupport');
      expect(transitiveNames).toContain('activerecord');
      expect(transitiveNames).toContain('concurrent-ruby');
      expect(transitiveNames).toContain('rack');
      expect(transitiveNames).toContain('warden');
    });

    it('generates correct purls for Rails gems', async () => {
      const lockfilePath = path.join(FIXTURES, 'ruby-service', 'Gemfile.lock');
      const result = await scanner.scan(path.join(FIXTURES, 'ruby-service'), lockfilePath);

      const devise = result.dependencies.find((d) => d.name === 'devise');
      expect(devise?.purl).toBe('pkg:gem/devise@4.9.3');

      const sidekiq = result.dependencies.find((d) => d.name === 'sidekiq');
      expect(sidekiq?.purl).toBe('pkg:gem/sidekiq@7.2.0');

      const activesupport = result.dependencies.find((d) => d.name === 'activesupport');
      expect(activesupport?.purl).toBe('pkg:gem/activesupport@7.1.2');
    });

    it('handles hyphenated gem names', async () => {
      const lockfilePath = path.join(FIXTURES, 'ruby-service', 'Gemfile.lock');
      const result = await scanner.scan(path.join(FIXTURES, 'ruby-service'), lockfilePath);

      const rackTest = result.dependencies.find((d) => d.name === 'rack-test');
      expect(rackTest).toBeDefined();
      expect(rackTest?.version).toBe('2.1.0');

      const redisClient = result.dependencies.find((d) => d.name === 'redis-client');
      expect(redisClient).toBeDefined();
      expect(redisClient?.version).toBe('0.19.1');
    });
  });
});
