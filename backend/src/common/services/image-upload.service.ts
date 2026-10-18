import { Injectable, BadRequestException } from '@nestjs/common';
import { extname, join } from 'path';
import { existsSync, mkdirSync, unlinkSync } from 'fs';
import { randomBytes } from 'crypto';

export interface UploadedFile {
  url: string;
  filename: string;
  originalName: string;
  size: number;
  mimeType: string;
}

@Injectable()
export class ImageUploadService {
  private readonly allowedMimeTypes = [
    'image/jpeg',
    'image/jpg',
    'image/png',
    'image/webp',
  ];

  private readonly allowedExtensions = ['.jpg', '.jpeg', '.png', '.webp'];

  private readonly maxFileSize = 5 * 1024 * 1024; // 5MB
  private readonly maxImages = 10;

  private readonly uploadDir = join(process.cwd(), 'uploads', 'images');

  constructor() {
    // Ensure upload directory exists
    if (!existsSync(this.uploadDir)) {
      mkdirSync(this.uploadDir, { recursive: true });
    }
  }

  validateFile(file: { originalname?: string; mimetype?: string; size?: number; buffer?: Buffer }): void {
    // Check if file exists
    if (!file) {
      throw new BadRequestException('No file provided');
    }

    // Validate MIME type (case-insensitive)
    const mimeLower = (file.mimetype || '').toLowerCase();
    if (!this.allowedMimeTypes.includes(mimeLower)) {
      throw new BadRequestException(
        `Invalid file type. Allowed types: ${this.allowedExtensions.join(', ')}`,
      );
    }

    // Validate extension
    const ext = extname(file.originalname || '').toLowerCase();
    if (!this.allowedExtensions.includes(ext)) {
      throw new BadRequestException(
        `Invalid file extension. Allowed extensions: ${this.allowedExtensions.join(', ')}`,
      );
    }

    // Validate file size (use buffer.length as source of truth, not file.size
    // which a malicious client could set to 0 or a small value to bypass the
    // check while still uploading > max bytes).
    const actualSize = file.buffer ? file.buffer.length : (file.size || 0);
    if (actualSize > this.maxFileSize) {
      throw new BadRequestException(
        `File size exceeds maximum limit of ${this.maxFileSize / 1024 / 1024}MB`,
      );
    }

    if (!file.buffer || file.buffer.length === 0) {
      throw new BadRequestException('No file content provided');
    }

    // Check for executable content (basic check)
    if (this.containsExecutableContent(file.buffer)) {
      throw new BadRequestException('File contains potentially executable content');
    }

    if (!this.matchesImageMagic(file.buffer, file.mimetype || '')) {
      throw new BadRequestException('File content does not match the declared image type');
    }
  }

  /**
   * JPEG / PNG / WebP magic must match the declared MIME type (IMG-03).
   */
  private matchesImageMagic(buffer: Buffer, mimetype: string): boolean {
    const mime = mimetype.toLowerCase();
    if (mime === 'image/jpeg' || mime === 'image/jpg') {
      return this.bufferStartsWith(buffer, [0xff, 0xd8, 0xff]);
    }
    if (mime === 'image/png') {
      return this.bufferStartsWith(buffer, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
    }
    if (mime === 'image/webp') {
      return (
        buffer.length >= 12 &&
        this.bufferStartsWith(buffer, [0x52, 0x49, 0x46, 0x46]) && // RIFF
        buffer[8] === 0x57 &&
        buffer[9] === 0x45 &&
        buffer[10] === 0x42 &&
        buffer[11] === 0x50 // WEBP
      );
    }
    return false;
  }

  /**
   * Scan the WHOLE buffer for executable signatures, not only the first bytes.
   * Polyglot attack: attacker prepends JPEG magic and hides ELF/PK/MZ/CAFEBABE
   * after some random bytes - the old version only checked the start of the
   * buffer and would let such files through as "JPEG".
   */
  private containsExecutableContent(buffer: Buffer): boolean {
    const signatures = [
      [0x4d, 0x5a], // EXE/DLL (MZ header)
      [0x7f, 0x45, 0x4c, 0x46], // ELF (Linux executable)
      [0x50, 0x4b, 0x03, 0x04], // ZIP (could contain executables)
      [0xca, 0xfe, 0xba, 0xbe], // Java class
    ];

    const maxOffset = Math.max(0, buffer.length - 4);
    for (let offset = 0; offset <= maxOffset; offset++) {
      for (const sig of signatures) {
        if (this.bufferStartsWithAt(buffer, sig, offset)) {
          return true;
        }
      }
    }
    return false;
  }

  private bufferStartsWithAt(buffer: Buffer, signature: number[], offset: number): boolean {
    if (buffer.length - offset < signature.length) return false;
    for (let i = 0; i < signature.length; i++) {
      if (buffer[offset + i] !== signature[i]) return false;
    }
    return true;
  }

  private bufferStartsWith(buffer: Buffer, signature: number[]): boolean {
    if (buffer.length < signature.length) return false;

    for (let i = 0; i < signature.length; i++) {
      if (buffer[i] !== signature[i]) return false;
    }
    return true;
  }

  async saveFile(file: { originalname?: string; mimetype?: string; size?: number; buffer?: Buffer }): Promise<UploadedFile> {
    this.validateFile(file);

    // Generate unique filename
    const ext = extname(file.originalname || '').toLowerCase();
    const filename = `${randomBytes(16).toString('hex')}${ext}`;

    return {
      url: `/uploads/images/${filename}`,
      filename,
      originalName: file.originalname || '',
      size: file.size || 0,
      mimeType: file.mimetype || '',
    };
  }

  async deleteFile(filename: string): Promise<void> {
    const filepath = join(this.uploadDir, filename);

    if (existsSync(filepath)) {
      unlinkSync(filepath);
    }
  }

  getMaxFileSize(): number {
    return this.maxFileSize;
  }

  getMaxImages(): number {
    return this.maxImages;
  }

  getAllowedExtensions(): string[] {
    return this.allowedExtensions;
  }
}
