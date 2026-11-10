#!/usr/bin/env node
// extract_aes_payload.js — statically decrypt the loader's encrypted module files.
//
// Mirrors the loader's decrypt path exactly, minus execution:
//   [16-byte IV][AES-256-CBC ciphertext]  --decrypt-->  brotli  --inflate-->  V8 code cache
//
// Usage:
//   node extract_aes_payload.js <key-hex> <input.js> [other.js ...] [--out DIR] [--keep-br]
//   KEY=<key-hex> node extract_aes_payload.js <input.js> [...]
//
// Outputs, next to each input (or under --out <dir>):
//   <name>.cache   — raw V8 code cache (feed this to View8 / v8dasm)
//   <name>.br      — the decrypted-but-still-compressed blob (kept with --keep-br)
//

'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const zlib = require('zlib');

const ALGO = 'aes-256-cbc';

function parseArgs(argv) {
  const opts = { out: null, keepBr: false, key: process.env.KEY || null, inputs: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--out') opts.out = argv[++i];
    else if (a === '--keep-br') opts.keepBr = true;
    else if (!opts.key && /^[0-9a-fA-F]{64}$/.test(a)) opts.key = a;
    else opts.inputs.push(a);
  }
  return opts;
}

function decrypt(buf, key) {
  const { ivLength } = crypto.getCipherInfo(ALGO);
  const iv = buf.subarray(0, ivLength);
  const ct = buf.subarray(ivLength);
  const d = crypto.createDecipheriv(ALGO, key, iv);
  return Buffer.concat([d.update(ct), d.final()]);
}

// Minimal V8 code-cache header parse (SerializedCodeData layout).
// Field order has been stable across recent V8: magic, version hash, source
// hash, flag hash, payload length, checksum. Reported for triage only.
function describeCache(cache) {
  if (cache.length < 24) return 'too short to be a V8 code cache';
  const u32 = (o) => cache.readUInt32LE(o);
  return [
    `magic=0x${u32(0).toString(16)}`,
    `version_hash=0x${u32(4).toString(16)}`,
    `source_hash=0x${u32(8).toString(16)} (source length ${u32(8)})`,
    `flag_hash=0x${u32(12).toString(16)}`,
    `payload_len=${u32(16)}`,
    `checksum=0x${u32(20).toString(16)}`,
  ].join(', ');
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (!opts.key || opts.inputs.length === 0) {
    console.error('usage: node extract_aes_payload.js <key-hex> <input.js> [...] [--out DIR] [--keep-br]');
    process.exit(2);
  }
  const key = Buffer.from(opts.key, 'hex');
  if (key.length !== 32) {
    console.error(`key must be 32 bytes (got ${key.length})`);
    process.exit(2);
  }
  if (opts.out) fs.mkdirSync(opts.out, { recursive: true });

  let failures = 0;
  for (const input of opts.inputs) {
    const base = path.basename(input).replace(/\.js$/, '');
    const dir = opts.out || path.dirname(input);
    try {
      const raw = fs.readFileSync(input);
      const br = decrypt(raw, key);
      if (opts.keepBr) fs.writeFileSync(path.join(dir, base + '.br'), br);
      const cache = zlib.brotliDecompressSync(br);
      const outPath = path.join(dir, base + '.decrypted');
      fs.writeFileSync(outPath, cache);
      console.log(`[+] ${input} -> ${outPath} (${cache.length} bytes)`);
      console.log(`    ${describeCache(cache)}`);
    } catch (e) {
      failures++;
      // "bad decrypt" => wrong key for this file; brotli error => key right, padding/format off.
      console.error(`[-] ${input}: ${e.message}`);
    }
  }
  process.exit(failures ? 1 : 0);
}

main();

