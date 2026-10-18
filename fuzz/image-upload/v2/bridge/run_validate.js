/* Node bridge: đọc buffer từ stdin, gọi ImageUploadService.validateFile() thật.
   Trả JSON kết quả ra stdout. Mỗi invocation là 1 process độc lập → crash thật. */
const path = require('path');
const fs = require('fs');

// Service được tsc compile ra compiled/image-upload.service.js (flat layout)
const COMPILED_DIR = path.resolve(__dirname, '..', 'compiled');
const SERVICE_PATH = path.join(COMPILED_DIR, 'image-upload.service.js');

let service;
try {
  service = require(SERVICE_PATH);
} catch (e) {
  // eslint-disable-next-line no-console
  console.log(JSON.stringify({
    outcome: 'LOAD_ERROR',
    reason: 'cannot load compiled service: ' + e.message,
    hint: 'run scripts/compile_bridge.js first',
  }));
  process.exit(2);
}

const { ImageUploadService } = service;
const svc = new ImageUploadService();

// Đọc toàn bộ stdin (binary safe)
const chunks = [];
process.stdin.on('data', (c) => chunks.push(c));
process.stdin.on('end', () => {
  const buf = Buffer.concat(chunks);
  const mime = process.env.FUZZ_MIME || 'image/jpeg';
  const name = process.env.FUZZ_NAME || 'fuzz.bin';

  const t0 = process.hrtime.bigint();
  try {
    svc.validateFile({
      originalname: name,
      mimetype: mime,
      size: buf.length,
      buffer: buf,
    });
    const elapsedMs = Number(process.hrtime.bigint() - t0) / 1e6;
    process.stdout.write(JSON.stringify({
      outcome: 'PASS',
      elapsed_ms: Math.round(elapsedMs * 1000) / 1000,
    }));
  } catch (e) {
    const elapsedMs = Number(process.hrtime.bigint() - t0) / 1e6;
    const reason = e && e.message ? e.message : String(e);
    process.stdout.write(JSON.stringify({
      outcome: 'REJECT',
      reason,
      elapsed_ms: Math.round(elapsedMs * 1000) / 1000,
    }));
  }
});
