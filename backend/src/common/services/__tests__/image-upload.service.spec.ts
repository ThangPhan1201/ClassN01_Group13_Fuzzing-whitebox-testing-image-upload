import { BadRequestException } from '@nestjs/common';
import { ImageUploadService } from '../image-upload.service';

describe('ImageUploadService', () => {
  let service: ImageUploadService;

  beforeEach(() => {
    service = new ImageUploadService();
  });

  const jpeg = Buffer.from([0xff, 0xd8, 0xff, 0xd9, 0x00, 0x01]);
  const png = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00]);
  const webp = Buffer.concat([
    Buffer.from('RIFF'),
    Buffer.from([0x10, 0x00, 0x00, 0x00]),
    Buffer.from('WEBP'),
    Buffer.from([0x00, 0x00, 0x00, 0x00]),
  ]);

  it('accepts a JPEG whose magic matches image/jpeg', () => {
    expect(() =>
      service.validateFile({
        originalname: 'photo.jpg',
        mimetype: 'image/jpeg',
        size: jpeg.length,
        buffer: jpeg,
      }),
    ).not.toThrow();
  });

  it('accepts PNG and WebP magic', () => {
    expect(() =>
      service.validateFile({
        originalname: 'a.png',
        mimetype: 'image/png',
        size: png.length,
        buffer: png,
      }),
    ).not.toThrow();
    expect(() =>
      service.validateFile({
        originalname: 'a.webp',
        mimetype: 'image/webp',
        size: webp.length,
        buffer: webp,
      }),
    ).not.toThrow();
  });

  it('rejects JPEG MIME with non-image bytes (IMG-03)', () => {
    expect(() =>
      service.validateFile({
        originalname: 'photo.jpg',
        mimetype: 'image/jpeg',
        size: 16,
        buffer: Buffer.from('NOTANIMAGEFILE!!'),
      }),
    ).toThrow(BadRequestException);
  });

  it('rejects ELF magic even with image MIME (IMG-MAGIC)', () => {
    const elf = Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x00, 0x00, 0x00, 0x00]);
    expect(() =>
      service.validateFile({
        originalname: 'photo.jpg',
        mimetype: 'image/jpeg',
        size: elf.length,
        buffer: elf,
      }),
    ).toThrow(/executable/i);
  });

  it('rejects missing buffer', () => {
    expect(() =>
      service.validateFile({
        originalname: 'photo.jpg',
        mimetype: 'image/jpeg',
        size: 10,
      }),
    ).toThrow(/No file content/);
  });

  it('rejects truncated JPEG (IMG-05)', () => {
    expect(() =>
      service.validateFile({
        originalname: 'photo.jpg',
        mimetype: 'image/jpeg',
        size: 1,
        buffer: Buffer.from([0xff]),
      }),
    ).toThrow(BadRequestException);
  });

  it('rejects oversized files (IMG-04)', () => {
    expect(() =>
      service.validateFile({
        originalname: 'photo.jpg',
        mimetype: 'image/jpeg',
        size: 5 * 1024 * 1024 + 1,
        buffer: jpeg,
      }),
    ).toThrow(/maximum limit/);
  });

  it('rejects invalid MIME (IMG-02)', () => {
    expect(() =>
      service.validateFile({
        originalname: 'photo.bin',
        mimetype: 'application/octet-stream',
        size: jpeg.length,
        buffer: jpeg,
      }),
    ).toThrow(/Invalid file type/);
  });

  // ─── Edge cases: valid formats ──────────────────────────────────────────────

  it('accepts JPEG with image/jpg MIME (alias)', () => {
    expect(() =>
      service.validateFile({
        originalname: 'photo.jpg',
        mimetype: 'image/jpg',
        size: jpeg.length,
        buffer: jpeg,
      }),
    ).not.toThrow();
  });

  it('accepts PNG with minimal PNG magic (single chunk)', () => {
    // Minimal PNG: signature + IHDR (13 bytes) + IEND
    const minimalPng = Buffer.from([
      0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, // PNG signature
      0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52, // IHDR length+type
      0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, // 1x1 dimensions
      0x08, 0x02, 0x00, 0x00, 0x00,                      // 8-bit RGB
      0x90, 0x77, 0x53, 0xde,                             // IHDR CRC
      0x00, 0x00, 0x00, 0x0c, 0x49, 0x44, 0x41, 0x54, // IEND length+type
      0x08, 0xd7, 0x63, 0xf8, 0x0f, 0x00, 0x00, 0x01, // compressed data
      0x01, 0x00, 0x05, 0xfe, 0x02, 0xfe,               // trailer
      0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, // IEND type
      0xae, 0x42, 0x60, 0x82,                             // IEND CRC
    ]);
    expect(() =>
      service.validateFile({
        originalname: 'tiny.png',
        mimetype: 'image/png',
        size: minimalPng.length,
        buffer: minimalPng,
      }),
    ).not.toThrow();
  });

  // ─── Edge cases: cross-magic (MIME says one thing, bytes say another) ──────

  it('rejects PNG MIME with JPEG magic bytes (cross-magic)', () => {
    expect(() =>
      service.validateFile({
        originalname: 'fake.png',
        mimetype: 'image/png',
        size: jpeg.length,
        buffer: jpeg, // JPEG magic but PNG MIME
      }),
    ).toThrow(BadRequestException);
  });

  it('rejects WebP MIME with PNG magic bytes', () => {
    expect(() =>
      service.validateFile({
        originalname: 'fake.webp',
        mimetype: 'image/webp',
        size: png.length,
        buffer: png,
      }),
    ).toThrow(BadRequestException);
  });

  it('rejects JPEG MIME with PNG magic bytes', () => {
    expect(() =>
      service.validateFile({
        originalname: 'fake.jpg',
        mimetype: 'image/jpeg',
        size: png.length,
        buffer: png,
      }),
    ).toThrow(BadRequestException);
  });

  // ─── Edge cases: empty / zero-size buffer ────────────────────────────────────

  it('rejects JPEG with empty buffer (0 bytes)', () => {
    expect(() =>
      service.validateFile({
        originalname: 'empty.jpg',
        mimetype: 'image/jpeg',
        size: 0,
        buffer: Buffer.alloc(0),
      }),
    ).toThrow(/No file content/);
  });

  it('rejects JPEG with size declared but no buffer object', () => {
    expect(() =>
      service.validateFile({
        originalname: 'noblffer.jpg',
        mimetype: 'image/jpeg',
        size: 100,
      } as any),
    ).toThrow(/No file content/);
  });

  // ─── Edge cases: weird signatures ────────────────────────────────────────────

  it('rejects ZIP magic (50 4B) even with image MIME', () => {
    const zipHeader = Buffer.from([0x50, 0x4b, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00]);
    expect(() =>
      service.validateFile({
        originalname: 'photo.jpg',
        mimetype: 'image/jpeg',
        size: zipHeader.length,
        buffer: zipHeader,
      }),
    ).toThrow(/executable/i);
  });

  it('rejects Java class magic (CA FE BA BE) with image MIME', () => {
    const classMagic = Buffer.from([0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x00]);
    expect(() =>
      service.validateFile({
        originalname: 'photo.jpg',
        mimetype: 'image/jpeg',
        size: classMagic.length,
        buffer: classMagic,
      }),
    ).toThrow(/executable/i);
  });

  // ─── Edge cases: truncated at exact magic length ─────────────────────────────

  it('rejects PNG buffer shorter than signature (7 bytes)', () => {
    // 7 bytes = incomplete PNG signature → bufferStartsWith returns false
    expect(() =>
      service.validateFile({
        originalname: 'truncated.png',
        mimetype: 'image/png',
        size: 7,
        buffer: Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a]),
      }),
    ).toThrow(BadRequestException);
  });

  it('rejects WebP buffer shorter than 12 bytes (missing WEBP)', () => {
    expect(() =>
      service.validateFile({
        originalname: 'short.webp',
        mimetype: 'image/webp',
        size: 8,
        buffer: Buffer.from([0x52, 0x49, 0x46, 0x46, 0x10, 0x00, 0x00, 0x00]),
      }),
    ).toThrow(BadRequestException);
  });

  // ─── Edge cases: valid WebP with extended header ─────────────────────────────

  it('accepts WebP with extended header (12 bytes, no RIFF padding)', () => {
    const webp12 = Buffer.concat([
      Buffer.from([0x52, 0x49, 0x46, 0x46]), // RIFF
      Buffer.from([0x0c, 0x00, 0x00, 0x00]), // file size - 8
      Buffer.from([0x57, 0x45, 0x42, 0x50]), // WEBP
      Buffer.from([0x00, 0x00, 0x00, 0x00]), // VP8 data
    ]);
    expect(() =>
      service.validateFile({
        originalname: 'valid.webp',
        mimetype: 'image/webp',
        size: webp12.length,
        buffer: webp12,
      }),
    ).not.toThrow();
  });
});
