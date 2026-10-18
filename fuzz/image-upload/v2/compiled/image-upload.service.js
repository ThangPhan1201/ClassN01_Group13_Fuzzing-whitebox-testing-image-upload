"use strict";
var __esDecorate = (this && this.__esDecorate) || function (ctor, descriptorIn, decorators, contextIn, initializers, extraInitializers) {
    function accept(f) { if (f !== void 0 && typeof f !== "function") throw new TypeError("Function expected"); return f; }
    var kind = contextIn.kind, key = kind === "getter" ? "get" : kind === "setter" ? "set" : "value";
    var target = !descriptorIn && ctor ? contextIn["static"] ? ctor : ctor.prototype : null;
    var descriptor = descriptorIn || (target ? Object.getOwnPropertyDescriptor(target, contextIn.name) : {});
    var _, done = false;
    for (var i = decorators.length - 1; i >= 0; i--) {
        var context = {};
        for (var p in contextIn) context[p] = p === "access" ? {} : contextIn[p];
        for (var p in contextIn.access) context.access[p] = contextIn.access[p];
        context.addInitializer = function (f) { if (done) throw new TypeError("Cannot add initializers after decoration has completed"); extraInitializers.push(accept(f || null)); };
        var result = (0, decorators[i])(kind === "accessor" ? { get: descriptor.get, set: descriptor.set } : descriptor[key], context);
        if (kind === "accessor") {
            if (result === void 0) continue;
            if (result === null || typeof result !== "object") throw new TypeError("Object expected");
            if (_ = accept(result.get)) descriptor.get = _;
            if (_ = accept(result.set)) descriptor.set = _;
            if (_ = accept(result.init)) initializers.unshift(_);
        }
        else if (_ = accept(result)) {
            if (kind === "field") initializers.unshift(_);
            else descriptor[key] = _;
        }
    }
    if (target) Object.defineProperty(target, contextIn.name, descriptor);
    done = true;
};
var __runInitializers = (this && this.__runInitializers) || function (thisArg, initializers, value) {
    var useValue = arguments.length > 2;
    for (var i = 0; i < initializers.length; i++) {
        value = useValue ? initializers[i].call(thisArg, value) : initializers[i].call(thisArg);
    }
    return useValue ? value : void 0;
};
var __setFunctionName = (this && this.__setFunctionName) || function (f, name, prefix) {
    if (typeof name === "symbol") name = name.description ? "[".concat(name.description, "]") : "";
    return Object.defineProperty(f, "name", { configurable: true, value: prefix ? "".concat(prefix, " ", name) : name });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ImageUploadService = void 0;
const common_1 = require("@nestjs/common");
const path_1 = require("path");
const fs_1 = require("fs");
const crypto_1 = require("crypto");
let ImageUploadService = (() => {
    let _classDecorators = [(0, common_1.Injectable)()];
    let _classDescriptor;
    let _classExtraInitializers = [];
    let _classThis;
    var ImageUploadService = _classThis = class {
        constructor() {
            this.allowedMimeTypes = [
                'image/jpeg',
                'image/jpg',
                'image/png',
                'image/webp',
            ];
            this.allowedExtensions = ['.jpg', '.jpeg', '.png', '.webp'];
            this.maxFileSize = 5 * 1024 * 1024; // 5MB
            this.maxImages = 10;
            this.uploadDir = (0, path_1.join)(process.cwd(), 'uploads', 'images');
            // Ensure upload directory exists
            if (!(0, fs_1.existsSync)(this.uploadDir)) {
                (0, fs_1.mkdirSync)(this.uploadDir, { recursive: true });
            }
        }
        validateFile(file) {
            // Check if file exists
            if (!file) {
                throw new common_1.BadRequestException('No file provided');
            }
            // Validate MIME type (case-insensitive)
            const mimeLower = (file.mimetype || '').toLowerCase();
            if (!this.allowedMimeTypes.includes(mimeLower)) {
                throw new common_1.BadRequestException(`Invalid file type. Allowed types: ${this.allowedExtensions.join(', ')}`);
            }
            // Validate extension
            const ext = (0, path_1.extname)(file.originalname || '').toLowerCase();
            if (!this.allowedExtensions.includes(ext)) {
                throw new common_1.BadRequestException(`Invalid file extension. Allowed extensions: ${this.allowedExtensions.join(', ')}`);
            }
            // Validate file size (use buffer.length as source of truth, not file.size
            // which a malicious client could set to 0 or a small value to bypass the
            // check while still uploading > max bytes).
            const actualSize = file.buffer ? file.buffer.length : (file.size || 0);
            if (actualSize > this.maxFileSize) {
                throw new common_1.BadRequestException(`File size exceeds maximum limit of ${this.maxFileSize / 1024 / 1024}MB`);
            }
            if (!file.buffer || file.buffer.length === 0) {
                throw new common_1.BadRequestException('No file content provided');
            }
            // Check for executable content (basic check)
            if (this.containsExecutableContent(file.buffer)) {
                throw new common_1.BadRequestException('File contains potentially executable content');
            }
            if (!this.matchesImageMagic(file.buffer, file.mimetype || '')) {
                throw new common_1.BadRequestException('File content does not match the declared image type');
            }
        }
        /**
         * JPEG / PNG / WebP magic must match the declared MIME type (IMG-03).
         */
        matchesImageMagic(buffer, mimetype) {
            const mime = mimetype.toLowerCase();
            if (mime === 'image/jpeg' || mime === 'image/jpg') {
                return this.bufferStartsWith(buffer, [0xff, 0xd8, 0xff]);
            }
            if (mime === 'image/png') {
                return this.bufferStartsWith(buffer, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
            }
            if (mime === 'image/webp') {
                return (buffer.length >= 12 &&
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
        containsExecutableContent(buffer) {
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
        bufferStartsWithAt(buffer, signature, offset) {
            if (buffer.length - offset < signature.length)
                return false;
            for (let i = 0; i < signature.length; i++) {
                if (buffer[offset + i] !== signature[i])
                    return false;
            }
            return true;
        }
        bufferStartsWith(buffer, signature) {
            if (buffer.length < signature.length)
                return false;
            for (let i = 0; i < signature.length; i++) {
                if (buffer[i] !== signature[i])
                    return false;
            }
            return true;
        }
        async saveFile(file) {
            this.validateFile(file);
            // Generate unique filename
            const ext = (0, path_1.extname)(file.originalname || '').toLowerCase();
            const filename = `${(0, crypto_1.randomBytes)(16).toString('hex')}${ext}`;
            return {
                url: `/uploads/images/${filename}`,
                filename,
                originalName: file.originalname || '',
                size: file.size || 0,
                mimeType: file.mimetype || '',
            };
        }
        async deleteFile(filename) {
            const filepath = (0, path_1.join)(this.uploadDir, filename);
            if ((0, fs_1.existsSync)(filepath)) {
                (0, fs_1.unlinkSync)(filepath);
            }
        }
        getMaxFileSize() {
            return this.maxFileSize;
        }
        getMaxImages() {
            return this.maxImages;
        }
        getAllowedExtensions() {
            return this.allowedExtensions;
        }
    };
    __setFunctionName(_classThis, "ImageUploadService");
    (() => {
        const _metadata = typeof Symbol === "function" && Symbol.metadata ? Object.create(null) : void 0;
        __esDecorate(null, _classDescriptor = { value: _classThis }, _classDecorators, { kind: "class", name: _classThis.name, metadata: _metadata }, null, _classExtraInitializers);
        ImageUploadService = _classThis = _classDescriptor.value;
        if (_metadata) Object.defineProperty(_classThis, Symbol.metadata, { enumerable: true, configurable: true, writable: true, value: _metadata });
        __runInitializers(_classThis, _classExtraInitializers);
    })();
    return ImageUploadService = _classThis;
})();
exports.ImageUploadService = ImageUploadService;
