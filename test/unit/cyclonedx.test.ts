import { describe, it, expect } from 'vitest';
import { CycloneDxGenerator } from '../../src/sbom/cyclonedx.js';
import { NpmScanner } from '../../src/scanners/npm/npm-scanner.js';
import path from 'path';

const FIXTURES = path.resolve(__dirname, '../fixtures');

describe('CycloneDxGenerator', () => {
  const generator = new CycloneDxGenerator();

  it('generates valid CycloneDX 1.7 JSON', async () => {
    const scanner = new NpmScanner();
    const lockfilePath = path.join(FIXTURES, 'node-api', 'package-lock.json');
    const scanResult = await scanner.scan(path.join(FIXTURES, 'node-api'), lockfilePath);

    const sbom = generator.generate(scanResult, '0.1.0');

    expect(sbom.format).toBe('cyclonedx-json');
    expect(sbom.specVersion).toBe('1.7');
    expect(sbom.componentCount).toBe(scanResult.dependencies.length);

    // Parse the content and validate structure
    const bom = JSON.parse(sbom.content);
    expect(bom.bomFormat).toBe('CycloneDX');
    expect(bom.specVersion).toBe('1.7');
    expect(bom.serialNumber).toMatch(/^urn:uuid:/);
    expect(bom.version).toBe(1);
  });

  it('includes tool metadata identifying Verimu', async () => {
    const scanner = new NpmScanner();
    const lockfilePath = path.join(FIXTURES, 'node-api', 'package-lock.json');
    const scanResult = await scanner.scan(path.join(FIXTURES, 'node-api'), lockfilePath);

    const sbom = generator.generate(scanResult, '0.1.0');
    const bom = JSON.parse(sbom.content);

    const tool = bom.metadata.tools.components[0];
    expect(tool.name).toBe('verimu');
    expect(tool.version).toBe('0.1.0');
  });

  it('maps all dependencies to CycloneDX components', async () => {
    const scanner = new NpmScanner();
    const lockfilePath = path.join(FIXTURES, 'node-api', 'package-lock.json');
    const scanResult = await scanner.scan(path.join(FIXTURES, 'node-api'), lockfilePath);

    const sbom = generator.generate(scanResult);
    const bom = JSON.parse(sbom.content);

    expect(bom.components.length).toBe(scanResult.dependencies.length);

    // Check a specific component
    const express = bom.components.find((c: any) => c.name === 'express');
    expect(express).toBeDefined();
    expect(express.type).toBe('library');
    expect(express.version).toBe('4.18.2');
    expect(express.purl).toBe('pkg:npm/express@4.18.2');
    expect(express['bom-ref']).toBe('pkg:npm/express@4.18.2');
    expect(express.scope).toBe('required'); // direct dep
  });

  it('marks transitive deps with optional scope', async () => {
    const scanner = new NpmScanner();
    const lockfilePath = path.join(FIXTURES, 'node-api', 'package-lock.json');
    const scanResult = await scanner.scan(path.join(FIXTURES, 'node-api'), lockfilePath);

    const sbom = generator.generate(scanResult);
    const bom = JSON.parse(sbom.content);

    const bodyParser = bom.components.find((c: any) => c.name === 'body-parser');
    expect(bodyParser?.scope).toBe('optional'); // transitive
  });

  it('includes dependency graph with single root node (NTIA compliance)', async () => {
    const scanner = new NpmScanner();
    const lockfilePath = path.join(FIXTURES, 'node-api', 'package-lock.json');
    const scanResult = await scanner.scan(path.join(FIXTURES, 'node-api'), lockfilePath);

    const sbom = generator.generate(scanResult);
    const bom = JSON.parse(sbom.content);

    expect(bom.dependencies).toBeDefined();

    // NTIA requires exactly one root node in the dependency graph
    expect(bom.dependencies).toHaveLength(1);

    const root = bom.dependencies[0];
    expect(root.ref).toBe('root-component');

    // Root should reference ALL dependencies (direct + transitive)
    expect(root.dependsOn).toContain('pkg:npm/express@4.18.2');
    expect(root.dependsOn).toContain('pkg:npm/body-parser@1.20.1'); // transitive
    expect(root.dependsOn.length).toBe(scanResult.dependencies.length);
  });

  it('produces different serial numbers each time', async () => {
    const scanner = new NpmScanner();
    const lockfilePath = path.join(FIXTURES, 'vue-app', 'package-lock.json');
    const scanResult = await scanner.scan(path.join(FIXTURES, 'vue-app'), lockfilePath);

    const sbom1 = generator.generate(scanResult);
    const sbom2 = generator.generate(scanResult);

    const bom1 = JSON.parse(sbom1.content);
    const bom2 = JSON.parse(sbom2.content);
    expect(bom1.serialNumber).not.toBe(bom2.serialNumber);
  });
});

describe('CycloneDxGenerator — NTIA supplier compliance', () => {
  const generator = new CycloneDxGenerator();

  it('includes metadata.supplier for NTIA compliance', async () => {
    const scanner = new NpmScanner();
    const lockfilePath = path.join(FIXTURES, 'node-api', 'package-lock.json');
    const scanResult = await scanner.scan(path.join(FIXTURES, 'node-api'), lockfilePath);

    const sbom = generator.generate(scanResult);
    const bom = JSON.parse(sbom.content);

    // NTIA requires metadata.supplier
    expect(bom.metadata.supplier).toBeDefined();
    expect(bom.metadata.supplier.name).toBe('node-api');

    // metadata.component should also have supplier
    expect(bom.metadata.component.supplier).toBeDefined();
    expect(bom.metadata.component.supplier.name).toBe('node-api');
  });

  it('includes supplier on every component', async () => {
    const scanner = new NpmScanner();
    const lockfilePath = path.join(FIXTURES, 'node-api', 'package-lock.json');
    const scanResult = await scanner.scan(path.join(FIXTURES, 'node-api'), lockfilePath);

    const sbom = generator.generate(scanResult);
    const bom = JSON.parse(sbom.content);

    // NTIA requires component.supplier on ALL components
    for (const component of bom.components) {
      expect(component.supplier).toBeDefined();
      expect(component.supplier.name).toBeTruthy();
    }

    // Unscoped package: supplier = package name
    const express = bom.components.find((c: any) => c.name === 'express');
    expect(express.supplier.name).toBe('express');
  });

  it('uses npm scope as supplier for scoped packages', async () => {
    const scanner = new NpmScanner();
    const lockfilePath = path.join(FIXTURES, 'vue-app', 'package-lock.json');
    const scanResult = await scanner.scan(path.join(FIXTURES, 'vue-app'), lockfilePath);

    const sbom = generator.generate(scanResult);
    const bom = JSON.parse(sbom.content);

    // @vue/reactivity → supplier should be "@vue"
    const vueReactivity = bom.components.find((c: any) => c.name === '@vue/reactivity');
    if (vueReactivity) {
      expect(vueReactivity.supplier.name).toBe('@vue');
    }
  });

  it('tool component includes Verimu as supplier', async () => {
    const scanner = new NpmScanner();
    const lockfilePath = path.join(FIXTURES, 'node-api', 'package-lock.json');
    const scanResult = await scanner.scan(path.join(FIXTURES, 'node-api'), lockfilePath);

    const sbom = generator.generate(scanResult);
    const bom = JSON.parse(sbom.content);

    const tool = bom.metadata.tools.components[0];
    expect(tool.supplier).toBeDefined();
    expect(tool.supplier.name).toBe('Verimu');
  });
});
