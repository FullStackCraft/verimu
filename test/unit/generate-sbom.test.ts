import { describe, it, expect } from 'vitest';
import { generateSbom } from '../../src/generate-sbom.js';

describe('generateSbom', () => {
  const baseInput = {
    projectName: 'my-app',
    projectVersion: '1.0.0',
    dependencies: [
      { name: 'express', version: '4.18.2', ecosystem: 'npm' as const },
      { name: '@types/node', version: '20.11.5', ecosystem: 'npm' as const, direct: false },
      { name: 'helmet', version: '7.1.0', ecosystem: 'npm' as const },
    ],
  };

  it('returns a valid CycloneDX 1.7 SBOM', () => {
    const result = generateSbom(baseInput);
    expect(result.specVersion).toBe('1.7');
    expect(result.componentCount).toBe(3);

    const sbom = result.sbom as any;
    expect(sbom.bomFormat).toBe('CycloneDX');
    expect(sbom.specVersion).toBe('1.7');
    expect(sbom.$schema).toContain('bom-1.7');
    expect(sbom.serialNumber).toMatch(/^urn:uuid:/);
  });

  it('returns both sbom object and content string', () => {
    const result = generateSbom(baseInput);
    expect(typeof result.content).toBe('string');
    expect(typeof result.sbom).toBe('object');
    expect(JSON.parse(result.content)).toEqual(result.sbom);
  });

  it('includes NTIA-required metadata supplier', () => {
    const result = generateSbom(baseInput);
    const sbom = result.sbom as any;
    expect(sbom.metadata.supplier).toEqual({ name: 'my-app' });
    expect(sbom.metadata.component.supplier).toEqual({ name: 'my-app' });
  });

  it('includes tool supplier (Verimu)', () => {
    const result = generateSbom(baseInput);
    const sbom = result.sbom as any;
    const tool = sbom.metadata.tools.components[0];
    expect(tool.name).toBe('verimu');
    expect(tool.supplier).toEqual({ name: 'Verimu' });
  });

  it('generates correct PURLs for unscoped packages', () => {
    const result = generateSbom(baseInput);
    const sbom = result.sbom as any;
    const express = sbom.components.find((c: any) => c.name === 'express');
    expect(express.purl).toBe('pkg:npm/express@4.18.2');
  });

  it('generates %40-encoded PURLs for scoped npm packages', () => {
    const result = generateSbom(baseInput);
    const sbom = result.sbom as any;
    const typesNode = sbom.components.find((c: any) => c.name === '@types/node');
    expect(typesNode.purl).toBe('pkg:npm/%40types/node@20.11.5');
  });

  it('derives supplier from scope for scoped packages', () => {
    const result = generateSbom(baseInput);
    const sbom = result.sbom as any;
    const typesNode = sbom.components.find((c: any) => c.name === '@types/node');
    expect(typesNode.supplier).toEqual({ name: '@types' });
  });

  it('uses package name as supplier for unscoped packages', () => {
    const result = generateSbom(baseInput);
    const sbom = result.sbom as any;
    const express = sbom.components.find((c: any) => c.name === 'express');
    expect(express.supplier).toEqual({ name: 'express' });
  });

  it('marks direct deps as required, transitive as optional', () => {
    const result = generateSbom(baseInput);
    const sbom = result.sbom as any;
    const express = sbom.components.find((c: any) => c.name === 'express');
    const typesNode = sbom.components.find((c: any) => c.name === '@types/node');
    expect(express.scope).toBe('required');
    expect(typesNode.scope).toBe('optional');
  });

  it('defaults direct to true when omitted', () => {
    const result = generateSbom({
      projectName: 'test',
      dependencies: [
        { name: 'lodash', version: '4.17.21', ecosystem: 'npm' },
      ],
    });
    const sbom = result.sbom as any;
    expect(sbom.components[0].scope).toBe('required');
  });

  it('builds single-root dependency graph (NTIA compliance)', () => {
    const result = generateSbom(baseInput);
    const sbom = result.sbom as any;
    expect(sbom.dependencies).toHaveLength(1);
    expect(sbom.dependencies[0].dependsOn).toHaveLength(3);
  });

  it('uses provided purl when given, skipping auto-generation', () => {
    const result = generateSbom({
      projectName: 'test',
      dependencies: [
        {
          name: 'custom-pkg',
          version: '1.0.0',
          ecosystem: 'npm',
          purl: 'pkg:npm/custom-pkg@1.0.0?qualifier=value',
        },
      ],
    });
    const sbom = result.sbom as any;
    expect(sbom.components[0].purl).toBe('pkg:npm/custom-pkg@1.0.0?qualifier=value');
  });

  it('defaults projectVersion to 0.0.0 when omitted', () => {
    const result = generateSbom({
      projectName: 'test',
      dependencies: [
        { name: 'express', version: '4.18.2', ecosystem: 'npm' },
      ],
    });
    const sbom = result.sbom as any;
    expect(sbom.metadata.component.version).toBe('0.0.0');
  });

  it('handles non-npm ecosystems (nuget, cargo)', () => {
    const result = generateSbom({
      projectName: 'my-service',
      projectVersion: '2.0.0',
      dependencies: [
        { name: 'Newtonsoft.Json', version: '13.0.3', ecosystem: 'nuget' },
        { name: 'serde', version: '1.0.195', ecosystem: 'cargo' },
      ],
    });
    const sbom = result.sbom as any;
    const nuget = sbom.components.find((c: any) => c.name === 'Newtonsoft.Json');
    const cargo = sbom.components.find((c: any) => c.name === 'serde');
    expect(nuget.purl).toBe('pkg:nuget/Newtonsoft.Json@13.0.3');
    expect(cargo.purl).toBe('pkg:cargo/serde@1.0.195');
  });

  it('handles empty dependency list', () => {
    const result = generateSbom({
      projectName: 'empty-project',
      dependencies: [],
    });
    expect(result.componentCount).toBe(0);
    const sbom = result.sbom as any;
    expect(sbom.components).toEqual([]);
    expect(sbom.dependencies[0].dependsOn).toEqual([]);
  });
});
