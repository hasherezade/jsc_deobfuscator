// decompress-jsc.js  — decompress only, zero execution
// run with: node.exe dump-jsc.js <target>.jsc

const fs = require("fs"), zlib = require("zlib");
for (const f of process.argv.slice(2)) {
  const out = zlib.brotliDecompressSync(fs.readFileSync(f));
  fs.writeFileSync(f + ".decompressed.jsc", out);
  console.error(`${f} -> ${out.length} bytes, magic 0x${out.readUInt32LE(0).toString(16)}`);
}

