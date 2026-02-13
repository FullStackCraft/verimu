import { describe, it, expect, vi } from 'vitest';
import { MavenScanner } from '../../src/scanners/maven/maven-scanner.js';
import path from 'path';

const FIXTURES = path.resolve(__dirname, '../fixtures');

describe('MavenScanner', () => {
  // Create scanner with a mock execSync that always fails (no Maven installed)
  // so it falls back to dependency-tree.txt
  const noMavenExec = vi.fn().mockImplementation(() => {
    throw new Error('mvn not found');
  }) as any;
  const scanner = new MavenScanner(noMavenExec);

  describe('detect()', () => {
    it('finds pom.xml in a Maven project', async () => {
      const result = await scanner.detect(path.join(FIXTURES, 'java-api'));
      expect(result).not.toBeNull();
      expect(result).toContain('pom.xml');
    });

    it('returns null for a project with no pom.xml', async () => {
      const result = await scanner.detect(path.join(FIXTURES, 'empty-project'));
      expect(result).toBeNull();
    });

    it('returns null for an npm project', async () => {
      const result = await scanner.detect(path.join(FIXTURES, 'node-api'));
      expect(result).toBeNull();
    });
  });

  describe('scan() — java-api fixture (synthetic)', () => {
    it('parses dependencies from dependency-tree.txt', async () => {
      const pomPath = path.join(FIXTURES, 'java-api', 'pom.xml');
      const result = await scanner.scan(path.join(FIXTURES, 'java-api'), pomPath);

      expect(result.ecosystem).toBe('maven');
      expect(result.dependencies.length).toBeGreaterThan(0);
    });

    it('extracts correct groupId:artifactId name format', async () => {
      const pomPath = path.join(FIXTURES, 'java-api', 'pom.xml');
      const result = await scanner.scan(path.join(FIXTURES, 'java-api'), pomPath);

      const names = result.dependencies.map((d) => d.name);
      expect(names).toContain('com.google.guava:guava');
      expect(names).toContain('org.slf4j:slf4j-api');
      expect(names).toContain('org.springframework.boot:spring-boot-starter-web');
    });

    it('extracts correct versions', async () => {
      const pomPath = path.join(FIXTURES, 'java-api', 'pom.xml');
      const result = await scanner.scan(path.join(FIXTURES, 'java-api'), pomPath);

      const guava = result.dependencies.find((d) => d.name === 'com.google.guava:guava');
      expect(guava?.version).toBe('32.1.3-jre');

      const slf4j = result.dependencies.find((d) => d.name === 'org.slf4j:slf4j-api');
      expect(slf4j?.version).toBe('2.0.9');
    });

    it('generates correct Maven purls', async () => {
      const pomPath = path.join(FIXTURES, 'java-api', 'pom.xml');
      const result = await scanner.scan(path.join(FIXTURES, 'java-api'), pomPath);

      const guava = result.dependencies.find((d) => d.name === 'com.google.guava:guava');
      expect(guava?.purl).toBe('pkg:maven/com.google.guava/guava@32.1.3-jre');

      const slf4j = result.dependencies.find((d) => d.name === 'org.slf4j:slf4j-api');
      expect(slf4j?.purl).toBe('pkg:maven/org.slf4j/slf4j-api@2.0.9');
    });

    it('marks deps from pom.xml as direct, transitive as non-direct', async () => {
      const pomPath = path.join(FIXTURES, 'java-api', 'pom.xml');
      const result = await scanner.scan(path.join(FIXTURES, 'java-api'), pomPath);

      // Direct deps (declared in pom.xml)
      const guava = result.dependencies.find((d) => d.name === 'com.google.guava:guava');
      expect(guava?.direct).toBe(true);

      const springStarter = result.dependencies.find(
        (d) => d.name === 'org.springframework.boot:spring-boot-starter-web'
      );
      expect(springStarter?.direct).toBe(true);

      const slf4j = result.dependencies.find((d) => d.name === 'org.slf4j:slf4j-api');
      expect(slf4j?.direct).toBe(true);

      // Transitive deps (not in pom.xml, pulled in by direct deps)
      const springCore = result.dependencies.find((d) => d.name === 'org.springframework:spring-core');
      expect(springCore?.direct).toBe(false);

      const failureaccess = result.dependencies.find(
        (d) => d.name === 'com.google.guava:failureaccess'
      );
      expect(failureaccess?.direct).toBe(false);

      const jackson = result.dependencies.find(
        (d) => d.name === 'com.fasterxml.jackson.core:jackson-databind'
      );
      expect(jackson?.direct).toBe(false);
    });

    it('sets ecosystem to maven for all dependencies', async () => {
      const pomPath = path.join(FIXTURES, 'java-api', 'pom.xml');
      const result = await scanner.scan(path.join(FIXTURES, 'java-api'), pomPath);

      expect(result.dependencies.every((d) => d.ecosystem === 'maven')).toBe(true);
    });

    it('sets scannedAt timestamp', async () => {
      const pomPath = path.join(FIXTURES, 'java-api', 'pom.xml');
      const result = await scanner.scan(path.join(FIXTURES, 'java-api'), pomPath);
      expect(result.scannedAt).toBeTruthy();
      expect(new Date(result.scannedAt).getTime()).not.toBeNaN();
    });
  });

  describe('scan() — java-spring fixture (real-world)', () => {
    it('parses a realistic Spring Boot project', async () => {
      const pomPath = path.join(FIXTURES, 'java-spring', 'pom.xml');
      const result = await scanner.scan(path.join(FIXTURES, 'java-spring'), pomPath);

      expect(result.ecosystem).toBe('maven');
      expect(result.dependencies.length).toBeGreaterThan(20);
    });

    it('includes Spring framework dependencies', async () => {
      const pomPath = path.join(FIXTURES, 'java-spring', 'pom.xml');
      const result = await scanner.scan(path.join(FIXTURES, 'java-spring'), pomPath);

      const names = result.dependencies.map((d) => d.name);
      expect(names).toContain('org.springframework.boot:spring-boot-starter-web');
      expect(names).toContain('org.springframework:spring-core');
      expect(names).toContain('org.springframework.security:spring-security-core');
      expect(names).toContain('org.hibernate.orm:hibernate-core');
      expect(names).toContain('org.postgresql:postgresql');
    });

    it('includes Jackson and logging dependencies', async () => {
      const pomPath = path.join(FIXTURES, 'java-spring', 'pom.xml');
      const result = await scanner.scan(path.join(FIXTURES, 'java-spring'), pomPath);

      const names = result.dependencies.map((d) => d.name);
      expect(names).toContain('com.fasterxml.jackson.core:jackson-databind');
      expect(names).toContain('ch.qos.logback:logback-classic');
      expect(names).toContain('org.slf4j:slf4j-api');
    });

    it('correctly identifies direct deps from pom.xml vs transitive', async () => {
      const pomPath = path.join(FIXTURES, 'java-spring', 'pom.xml');
      const result = await scanner.scan(path.join(FIXTURES, 'java-spring'), pomPath);

      // Direct deps from pom.xml
      const starterWeb = result.dependencies.find(
        (d) => d.name === 'org.springframework.boot:spring-boot-starter-web'
      );
      expect(starterWeb?.direct).toBe(true);

      const postgresql = result.dependencies.find((d) => d.name === 'org.postgresql:postgresql');
      expect(postgresql?.direct).toBe(true);

      // Transitive deps (not in pom.xml)
      const springCore = result.dependencies.find((d) => d.name === 'org.springframework:spring-core');
      expect(springCore?.direct).toBe(false);

      const hibernate = result.dependencies.find((d) => d.name === 'org.hibernate.orm:hibernate-core');
      expect(hibernate?.direct).toBe(false);

      const securityCore = result.dependencies.find(
        (d) => d.name === 'org.springframework.security:spring-security-core'
      );
      expect(securityCore?.direct).toBe(false);
    });
  });

  describe('error handling', () => {
    it('throws when no mvn and no dependency-tree.txt', async () => {
      const pomPath = path.join(FIXTURES, 'empty-project', 'pom.xml');
      // empty-project has no pom.xml nor dependency-tree.txt
      // but we pass a fake pom path — it should fail trying to resolve deps
      await expect(
        scanner.scan(path.join(FIXTURES, 'empty-project'), pomPath)
      ).rejects.toThrow();
    });
  });
});
