import path from 'path';

(async () => {
  try {
    // prefer compiled JS in dist (built by `npm run build`), fallback to src if present
    let mod;
    try {
      mod = await import(new URL('../dist/scan.js', import.meta.url));
    } catch (_) {
      mod = await import(new URL('../src/scan.js', import.meta.url));
    }
    const { scan } = mod;

    const projectPath = path.join(process.cwd(), 'test', 'fixtures', 'node-api');
    const out = path.join(process.cwd(), 'test-sbom.keep.cdx.json');

    console.log('Scanning project:', projectPath);
    const report = await scan({ projectPath, sbomOutput: out, skipCveCheck: true });

    console.log('Wrote SBOM:', out);
    console.log('Components:', report.sbom.componentCount);
  } catch (err) {
    console.error('Scan failed:', err);
    process.exit(1);
  }
})();
