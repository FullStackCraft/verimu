import path from 'path';

(async () => {
  try {
    // Import from compiled dist (built by `npm run build`)
    const mod = await import(new URL('../dist/index.mjs', import.meta.url));
    const { scan } = mod;

    const projectPath = path.join(process.cwd(), 'test', 'fixtures', 'node-api');
    const out = path.join(process.cwd(), 'test-sbom.keep.cdx.json');

    console.log('Scanning project:', projectPath);
    const report = await scan({ projectPath, sbomOutput: out, skipCveCheck: true });

    console.log('Wrote SBOM:', out);
    console.log('Components:', report.sbom.componentCount);
  } catch (err) {
    if (err.code === 'ERR_MODULE_NOT_FOUND') {
      console.error('Error: dist/index.mjs not found. Please run "npm run build" first.');
    } else {
      console.error('Scan failed:', err);
    }
    process.exit(1);
  }
})();
