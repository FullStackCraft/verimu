import { describe, it, expect } from 'vitest';
import { NugetScanner } from '../../src/scanners/nuget/nuget-scanner.js';
import path from 'path';

const FIXTURES = path.resolve(__dirname, '../fixtures');

describe('NugetScanner', () => {
  const scanner = new NugetScanner();

  describe('detect()', () => {
    it('finds packages.lock.json in a .NET project', async () => {
      const result = await scanner.detect(path.join(FIXTURES, 'dotnet-api'));
      expect(result).not.toBeNull();
      expect(result).toContain('packages.lock.json');
    });

    it('returns null for a project with no NuGet lockfile', async () => {
      const result = await scanner.detect(path.join(FIXTURES, 'empty-project'));
      expect(result).toBeNull();
    });

    it('returns null for an npm project (no packages.lock.json)', async () => {
      const result = await scanner.detect(path.join(FIXTURES, 'node-api'));
      expect(result).toBeNull();
    });
  });

  describe('scan() — dotnet-api fixture (synthetic)', () => {
    it('parses all dependencies from NuGet lock file', async () => {
      const lockfilePath = path.join(FIXTURES, 'dotnet-api', 'packages.lock.json');
      const result = await scanner.scan(path.join(FIXTURES, 'dotnet-api'), lockfilePath);

      expect(result.ecosystem).toBe('nuget');
      expect(result.dependencies.length).toBe(6);
    });

    it('correctly identifies direct vs transitive dependencies', async () => {
      const lockfilePath = path.join(FIXTURES, 'dotnet-api', 'packages.lock.json');
      const result = await scanner.scan(path.join(FIXTURES, 'dotnet-api'), lockfilePath);

      const directDeps = result.dependencies.filter((d) => d.direct);
      const directNames = directDeps.map((d) => d.name).sort();
      expect(directNames).toEqual([
        'Microsoft.EntityFrameworkCore',
        'Newtonsoft.Json',
        'Serilog',
      ]);

      const transitiveDeps = result.dependencies.filter((d) => !d.direct);
      const transitiveNames = transitiveDeps.map((d) => d.name).sort();
      expect(transitiveNames).toEqual([
        'Microsoft.Extensions.DependencyInjection.Abstractions',
        'Microsoft.Extensions.Logging.Abstractions',
        'Serilog.Sinks.Console',
      ]);
    });

    it('generates correct NuGet purls', async () => {
      const lockfilePath = path.join(FIXTURES, 'dotnet-api', 'packages.lock.json');
      const result = await scanner.scan(path.join(FIXTURES, 'dotnet-api'), lockfilePath);

      const newtonsoft = result.dependencies.find((d) => d.name === 'Newtonsoft.Json');
      expect(newtonsoft?.purl).toBe('pkg:nuget/Newtonsoft.Json@13.0.3');

      const serilog = result.dependencies.find((d) => d.name === 'Serilog');
      expect(serilog?.purl).toBe('pkg:nuget/Serilog@3.1.1');
    });

    it('sets ecosystem to nuget for all dependencies', async () => {
      const lockfilePath = path.join(FIXTURES, 'dotnet-api', 'packages.lock.json');
      const result = await scanner.scan(path.join(FIXTURES, 'dotnet-api'), lockfilePath);

      expect(result.dependencies.every((d) => d.ecosystem === 'nuget')).toBe(true);
    });

    it('sets scannedAt timestamp', async () => {
      const lockfilePath = path.join(FIXTURES, 'dotnet-api', 'packages.lock.json');
      const result = await scanner.scan(path.join(FIXTURES, 'dotnet-api'), lockfilePath);
      expect(result.scannedAt).toBeTruthy();
      expect(new Date(result.scannedAt).getTime()).not.toBeNaN();
    });
  });

  describe('scan() — dotnet-webapi fixture (real-world)', () => {
    it('parses a realistic ASP.NET project with many dependencies', async () => {
      const lockfilePath = path.join(FIXTURES, 'dotnet-webapi', 'packages.lock.json');
      const result = await scanner.scan(path.join(FIXTURES, 'dotnet-webapi'), lockfilePath);

      expect(result.ecosystem).toBe('nuget');
      expect(result.dependencies.length).toBe(20);
    });

    it('identifies all direct dependencies', async () => {
      const lockfilePath = path.join(FIXTURES, 'dotnet-webapi', 'packages.lock.json');
      const result = await scanner.scan(path.join(FIXTURES, 'dotnet-webapi'), lockfilePath);

      const directDeps = result.dependencies.filter((d) => d.direct);
      const directNames = directDeps.map((d) => d.name).sort();
      expect(directNames).toEqual([
        'AutoMapper',
        'FluentValidation',
        'MediatR',
        'Microsoft.AspNetCore.Authentication.JwtBearer',
        'Microsoft.EntityFrameworkCore.SqlServer',
        'Serilog.AspNetCore',
        'Swashbuckle.AspNetCore',
      ]);
    });

    it('includes transitive dependencies from EF Core', async () => {
      const lockfilePath = path.join(FIXTURES, 'dotnet-webapi', 'packages.lock.json');
      const result = await scanner.scan(path.join(FIXTURES, 'dotnet-webapi'), lockfilePath);

      const transitiveNames = result.dependencies
        .filter((d) => !d.direct)
        .map((d) => d.name);

      expect(transitiveNames).toContain('Microsoft.EntityFrameworkCore');
      expect(transitiveNames).toContain('Microsoft.EntityFrameworkCore.Relational');
      expect(transitiveNames).toContain('Microsoft.Extensions.Logging');
    });
  });
});
