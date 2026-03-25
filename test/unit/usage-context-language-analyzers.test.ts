import { mkdtemp, mkdir, rm, writeFile } from 'fs/promises';
import os from 'os';
import path from 'path';
import { describe, expect, it } from 'vitest';
import type { Ecosystem } from '../../src/core/types.js';
import type { UsageContextAnalyzer } from '../../src/context/analyzers/analyzer.interface.js';
import { GoAstAnalyzer } from '../../src/context/analyzers/go-ast-analyzer.js';
import { PythonAstAnalyzer } from '../../src/context/analyzers/python-ast-analyzer.js';
import { JavaAstAnalyzer } from '../../src/context/analyzers/java-ast-analyzer.js';
import { DotnetAstAnalyzer } from '../../src/context/analyzers/dotnet-ast-analyzer.js';
import { RustAstAnalyzer } from '../../src/context/analyzers/rust-ast-analyzer.js';
import { RubyAstAnalyzer } from '../../src/context/analyzers/ruby-ast-analyzer.js';
import { PhpAstAnalyzer } from '../../src/context/analyzers/php-ast-analyzer.js';

async function withTempProject<T>(run: (projectPath: string) => Promise<T>): Promise<T> {
  const tmpDir = await mkdtemp(path.join(os.tmpdir(), 'verimu-usage-language-'));
  try {
    return await run(tmpDir);
  } finally {
    await rm(tmpDir, { recursive: true, force: true });
  }
}

async function runAnalyzer(params: {
  analyzer: UsageContextAnalyzer;
  ecosystem: Ecosystem;
  packageName: string;
  relativePath: string;
  source: string;
}) {
  return withTempProject(async (projectPath) => {
    const fullPath = path.join(projectPath, params.relativePath);
    await mkdir(path.dirname(fullPath), { recursive: true });
    await writeFile(fullPath, params.source, 'utf-8');

    const result = await params.analyzer.analyze({
      projectPath,
      ecosystem: params.ecosystem,
      numContextLines: 2,
      maxSnippetsPerPackage: 20,
      maxSnippetsTotal: 100,
      packages: [
        {
          packageName: params.packageName,
          ecosystem: params.ecosystem,
          directDependency: true,
          vulnerabilities: [],
        },
      ],
    });

    expect(result.errors).toHaveLength(0);
    expect(result.packages).toHaveLength(1);
    return result.packages[0];
  });
}

describe('Language analyzers', () => {
  it('Go analyzer finds import and call evidence', async () => {
    const finding = await runAnalyzer({
      analyzer: new GoAstAnalyzer(),
      ecosystem: 'go',
      packageName: 'github.com/dgrijalva/jwt-go',
      relativePath: 'main.go',
      source: [
        'package main',
        '',
        'import jwt "github.com/dgrijalva/jwt-go"',
        '',
        'func main() {',
        '  _ = jwt.New(jwt.SigningMethodHS256)',
        '}',
      ].join('\n'),
    });

    expect(finding.status).toBe('direct_evidence');
    expect(finding.snippets.some((snippet) => snippet.matchKind === 'import')).toBe(true);
    expect(finding.snippets.some((snippet) => snippet.matchKind === 'call')).toBe(true);
  });

  it('Go analyzer reports indirect_no_evidence when package is unused', async () => {
    const finding = await runAnalyzer({
      analyzer: new GoAstAnalyzer(),
      ecosystem: 'go',
      packageName: 'github.com/dgrijalva/jwt-go',
      relativePath: 'main.go',
      source: 'package main\nfunc main() {}\n',
    });

    expect(finding.status).toBe('indirect_no_evidence');
    expect(finding.snippets).toHaveLength(0);
  });

  it('Python analyzer finds import and call evidence', async () => {
    const finding = await runAnalyzer({
      analyzer: new PythonAstAnalyzer(),
      ecosystem: 'pip',
      packageName: 'pyyaml',
      relativePath: 'app.py',
      source: [
        'import yaml',
        '',
        'payload = yaml.load("a: 1", Loader=yaml.UnsafeLoader)',
      ].join('\n'),
    });

    expect(finding.status).toBe('direct_evidence');
    expect(finding.snippets.some((snippet) => snippet.matchKind === 'import')).toBe(true);
    expect(finding.snippets.some((snippet) => snippet.matchKind === 'call')).toBe(true);
  });

  it('Python analyzer reports indirect_no_evidence when package is unused', async () => {
    const finding = await runAnalyzer({
      analyzer: new PythonAstAnalyzer(),
      ecosystem: 'pip',
      packageName: 'pyyaml',
      relativePath: 'app.py',
      source: 'print("hello")\n',
    });

    expect(finding.status).toBe('indirect_no_evidence');
    expect(finding.snippets).toHaveLength(0);
  });

  it('Java analyzer finds import and call evidence', async () => {
    const finding = await runAnalyzer({
      analyzer: new JavaAstAnalyzer(),
      ecosystem: 'maven',
      packageName: 'org.apache.logging.log4j:log4j-core',
      relativePath: 'src/main/java/com/example/App.java',
      source: [
        'import org.apache.logging.log4j.LogManager;',
        'import org.apache.logging.log4j.Logger;',
        '',
        'public class App {',
        '  private static final Logger logger = LogManager.getLogger(App.class);',
        '  public static void main(String[] args) {',
        '    logger.info("demo");',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(finding.status).toBe('direct_evidence');
    expect(finding.snippets.some((snippet) => snippet.matchKind === 'import')).toBe(true);
    expect(finding.snippets.some((snippet) => snippet.matchKind === 'call')).toBe(true);
  });

  it('Java analyzer reports indirect_no_evidence when package is unused', async () => {
    const finding = await runAnalyzer({
      analyzer: new JavaAstAnalyzer(),
      ecosystem: 'maven',
      packageName: 'org.apache.logging.log4j:log4j-core',
      relativePath: 'src/main/java/com/example/App.java',
      source: 'public class App { public static void main(String[] args) {} }',
    });

    expect(finding.status).toBe('indirect_no_evidence');
    expect(finding.snippets).toHaveLength(0);
  });

  it('Dotnet analyzer finds using and call evidence', async () => {
    const finding = await runAnalyzer({
      analyzer: new DotnetAstAnalyzer(),
      ecosystem: 'nuget',
      packageName: 'Newtonsoft.Json',
      relativePath: 'Program.cs',
      source: [
        'using Json = Newtonsoft.Json.JsonConvert;',
        '',
        'public class Program {',
        '  public static void Main() {',
        '    var x = Json.SerializeObject(new { Name = "demo" });',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(finding.status).toBe('direct_evidence');
    expect(finding.snippets.some((snippet) => snippet.matchKind === 'import')).toBe(true);
    expect(finding.snippets.some((snippet) => snippet.matchKind === 'call')).toBe(true);
  });

  it('Dotnet analyzer reports indirect_no_evidence when package is unused', async () => {
    const finding = await runAnalyzer({
      analyzer: new DotnetAstAnalyzer(),
      ecosystem: 'nuget',
      packageName: 'Newtonsoft.Json',
      relativePath: 'Program.cs',
      source: 'Console.WriteLine("ok");',
    });

    expect(finding.status).toBe('indirect_no_evidence');
    expect(finding.snippets).toHaveLength(0);
  });

  it('Rust analyzer finds use and call evidence', async () => {
    const finding = await runAnalyzer({
      analyzer: new RustAstAnalyzer(),
      ecosystem: 'cargo',
      packageName: 'serde-json',
      relativePath: 'src/main.rs',
      source: [
        'use serde_json::Value;',
        '',
        'fn main() {',
        '  let _v: Value = serde_json::from_str("{\\"a\\":1}").unwrap();',
        '}',
      ].join('\n'),
    });

    expect(finding.status).toBe('direct_evidence');
    expect(finding.snippets.some((snippet) => snippet.matchKind === 'import')).toBe(true);
    expect(finding.snippets.some((snippet) => snippet.matchKind === 'call')).toBe(true);
  });

  it('Rust analyzer reports indirect_no_evidence when package is unused', async () => {
    const finding = await runAnalyzer({
      analyzer: new RustAstAnalyzer(),
      ecosystem: 'cargo',
      packageName: 'serde-json',
      relativePath: 'src/main.rs',
      source: 'fn main() { println!("ok"); }',
    });

    expect(finding.status).toBe('indirect_no_evidence');
    expect(finding.snippets).toHaveLength(0);
  });

  it('Ruby analyzer finds require and call evidence', async () => {
    const finding = await runAnalyzer({
      analyzer: new RubyAstAnalyzer(),
      ecosystem: 'ruby',
      packageName: 'active_support',
      relativePath: 'app.rb',
      source: [
        "require 'active_support'",
        '',
        "ActiveSupport::Inflector.camelize('demo')",
      ].join('\n'),
    });

    expect(finding.status).toBe('direct_evidence');
    expect(finding.snippets.some((snippet) => snippet.matchKind === 'require')).toBe(true);
    expect(finding.snippets.some((snippet) => snippet.matchKind === 'call')).toBe(true);
  });

  it('Ruby analyzer reports indirect_no_evidence when package is unused', async () => {
    const finding = await runAnalyzer({
      analyzer: new RubyAstAnalyzer(),
      ecosystem: 'ruby',
      packageName: 'active_support',
      relativePath: 'app.rb',
      source: "puts 'ok'\n",
    });

    expect(finding.status).toBe('indirect_no_evidence');
    expect(finding.snippets).toHaveLength(0);
  });

  it('PHP analyzer finds use and static-call evidence', async () => {
    const finding = await runAnalyzer({
      analyzer: new PhpAstAnalyzer(),
      ecosystem: 'composer',
      packageName: 'phpunit/phpunit',
      relativePath: 'Demo.php',
      source: [
        '<?php',
        '',
        'use PHPUnit\\Framework\\TestCase;',
        '',
        'TestCase::assertTrue(true);',
      ].join('\n'),
    });

    expect(finding.status).toBe('direct_evidence');
    expect(finding.snippets.some((snippet) => snippet.matchKind === 'import')).toBe(true);
    expect(finding.snippets.some((snippet) => snippet.matchKind === 'call')).toBe(true);
  });

  it('PHP analyzer reports indirect_no_evidence when package is unused', async () => {
    const finding = await runAnalyzer({
      analyzer: new PhpAstAnalyzer(),
      ecosystem: 'composer',
      packageName: 'phpunit/phpunit',
      relativePath: 'Demo.php',
      source: '<?php echo "ok";',
    });

    expect(finding.status).toBe('indirect_no_evidence');
    expect(finding.snippets).toHaveLength(0);
  });
});
