import path from 'path';

(async () => {
  try {
    // Load the built package entrypoint (self-scan job runs `npm run build` first).
    let scan;
    try {
      ({ scan } = await import(new URL('../dist/index.mjs', import.meta.url)));
    } catch (_) {
      ({ scan } = await import(new URL('../dist/index.cjs', import.meta.url)));
    }

    if (typeof scan !== 'function') {
      throw new Error('scan export not found in dist build output');
    }

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
