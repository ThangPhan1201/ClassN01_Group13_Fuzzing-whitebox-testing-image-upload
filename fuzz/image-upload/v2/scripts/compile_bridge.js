#!/usr/bin/env node
/* Compile file .ts thật của ImageUploadService thành CommonJS.
   Chạy 1 lần trước khi fuzz. */
const { execSync } = require('child_process');
const path = require('path');
const fs = require('fs');

const SCRIPT_DIR = __dirname;
const V2_DIR = path.resolve(SCRIPT_DIR, '..');
const FUZZ_DIR = path.resolve(V2_DIR, '..');
const ROOT = path.resolve(FUZZ_DIR, '..', '..');

const BACKEND_SRC = path.join(
  ROOT, 'backend', 'src', 'common', 'services', 'image-upload.service.ts'
);
const OUT_DIR = path.join(V2_DIR, 'compiled');

console.log('ROOT         =', ROOT);
console.log('BACKEND_SRC  =', BACKEND_SRC);
console.log('OUT_DIR      =', OUT_DIR);

if (!fs.existsSync(BACKEND_SRC)) {
  console.error('❌ Cannot find:', BACKEND_SRC);
  process.exit(1);
}

const TSC_BIN = path.join(ROOT, 'node_modules', '.bin', 'tsc');
if (!fs.existsSync(TSC_BIN)) {
  console.error('❌ tsc not found at', TSC_BIN);
  console.error('   Run: cd', ROOT, '&& npm install');
  process.exit(1);
}

fs.mkdirSync(OUT_DIR, { recursive: true });

console.log('Compiling...');
execSync(
  `"${TSC_BIN}" "${BACKEND_SRC}" --outDir "${OUT_DIR}" ` +
  `--target ES2020 --module commonjs --esModuleInterop true --skipLibCheck`,
  { stdio: 'inherit' }
);
console.log('✅ Compiled.');
