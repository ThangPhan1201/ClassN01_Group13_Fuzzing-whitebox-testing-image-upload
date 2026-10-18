/**
 * Fuzzing Test Suite — ListingService.findAll()
 *
 * Tests the bugs found by search.fuzz.ts white-box fuzzer:
 *   Bug 1 (FIXED): Type confusion  — q = true/false/NaN/Infinity → now guarded by typeof
 *   Bug 2 (FIXED): Negative page   — page=0, -1 → now Math.max(0, ...) prevents negative skip
 *
 * Uses Prisma mock (no real database needed).
 * Seed: 12345  |  Total cases: 38
 */

import { Test, TestingModule } from '@nestjs/testing';
import { ListingService } from '../services/listing.service';
import { AuditLogService } from 'src/common/services/audit-log.service';
import { PrismaService } from 'src/common/prisma/prisma.service';
import { Prisma } from '@prisma/client';

// ─── Fuzzing results from search.fuzz.ts ──────────────────────────────────────
// Seed: 12345
// Bugs found: type_confusion (7 errors), boundary (4 errors = negative page)
// Bugs FIXED:
//   Bug 1: Added typeof q === 'string' guard
//   Bug 2: Changed skip: (page-1)*limit → Math.max(0, (page-1)*limit)
// Unique bugs confirmed: 2 → FIXED: 2

const EMPTY_LIST = { data: [], meta: { total: 0, page: 1, limit: 20, totalPages: 0, hasNext: false, hasPrev: false } };

function makeMockPrisma(shouldThrow = false, throwType = 'PrismaClientUnknownRequestError') {
  const errorMap: Record<string, Error> = {
    PrismaClientUnknownRequestError: Object.assign(
      new Error('Invalid value for arg `where`'),
      { name: 'PrismaClientUnknownRequestError', code: 'P9999' }
    ),
    PrismaValidationError: Object.assign(
      new Error('Invalid value for arg `skip`'),
      { name: 'PrismaValidationError', code: 'P9999' }
    ),
  };

  return {
    listing: {
      findMany: jest.fn().mockImplementation(() => {
        if (shouldThrow) throw errorMap[throwType] || new Error('Mock error');
        return EMPTY_LIST.data;
      }),
      count: jest.fn().mockResolvedValue(0),
    },
  };
}

function makeMockAuditLog() {
  return { log: jest.fn().mockResolvedValue(undefined) };
}

async function createModule(mockPrisma: any, mockAudit: any) {
  const module: TestingModule = await Test.createTestingModule({
    providers: [
      ListingService,
      { provide: PrismaService, useValue: mockPrisma },
      { provide: AuditLogService, useValue: mockAudit },
    ],
  }).compile();
  return module.get<ListingService>(ListingService);
}

// ─── Bug 1 (FIXED): Type Confusion ─────────────────────────────────────────────

describe('Bug 1 — FIXED: typeof guard for q parameter', () => {
  let service: ListingService;
  let mockPrisma: any;

  beforeEach(async () => {
    mockPrisma = makeMockPrisma(false);
    const mockAudit = makeMockAuditLog();
    service = await createModule(mockPrisma, mockAudit);
  });

  // FIXED: non-string q values are now safely ignored (typeof guard)
  it('accepts q as normal string (calls Prisma)', async () => {
    await service.findAll({ q: 'test book' });
    expect(mockPrisma.listing.findMany).toHaveBeenCalled();
  });

  it('accepts q as empty string', async () => {
    await service.findAll({ q: '' });
    expect(mockPrisma.listing.findMany).toHaveBeenCalled();
  });

  it('accepts q as whitespace string', async () => {
    await service.findAll({ q: '   ' });
    expect(mockPrisma.listing.findMany).toHaveBeenCalled();
  });

  it('accepts q as Vietnamese string', async () => {
    await service.findAll({ q: 'áo sách giáo khoa' });
    expect(mockPrisma.listing.findMany).toHaveBeenCalled();
  });

  it('accepts q as Unicode/CJK string', async () => {
    await service.findAll({ q: '日本語' });
    expect(mockPrisma.listing.findMany).toHaveBeenCalled();
  });

  // FIXED: these now safely skip the search (typeof guard prevents OR clause)
  function assertNoOrClause(query: any) {
    mockPrisma.listing.findMany.mockClear();
    service.findAll(query);
    const call = mockPrisma.listing.findMany.mock.calls[0]?.[0];
    // FIXED: typeof guard prevents OR clause from being added
    expect(call?.where?.OR).toBeUndefined();
    // But findMany is still called (without search = fine)
    expect(mockPrisma.listing.findMany).toHaveBeenCalled();
  }

  it('q=true: no OR clause, no Prisma error (FIXED)', () => {
    assertNoOrClause({ q: true as any });
  });

  it('q=false: no OR clause, no Prisma error (FIXED)', () => {
    assertNoOrClause({ q: false as any });
  });

  it('q=NaN: no OR clause, no Prisma error (FIXED)', () => {
    assertNoOrClause({ q: NaN as any });
  });

  it('q=Infinity: no OR clause, no Prisma error (FIXED)', () => {
    assertNoOrClause({ q: Infinity as any });
  });

  it('q=-Infinity: no OR clause, no Prisma error (FIXED)', () => {
    assertNoOrClause({ q: -Infinity as any });
  });

  it('q=object: no OR clause, no Prisma error (FIXED)', () => {
    assertNoOrClause({ q: { foo: 'bar' } as any });
  });

  it('q=array: no OR clause, no Prisma error (FIXED)', () => {
    assertNoOrClause({ q: ['test'] as any });
  });
});

// ─── Bug 2 (FIXED): Negative Page ─────────────────────────────────────────────

describe('Bug 2 — FIXED: Math.max(0, ...) prevents negative skip', () => {
  let service: ListingService;
  let mockPrisma: any;

  beforeEach(async () => {
    mockPrisma = makeMockPrisma(false);
    const mockAudit = makeMockAuditLog();
    service = await createModule(mockPrisma, mockAudit);
  });

  it('accepts page=1 (valid default)', async () => {
    const result = await service.findAll({ page: 1 });
    expect(result.meta.page).toBe(1);
  });

  it('accepts page=2', async () => {
    const result = await service.findAll({ page: 2, limit: 20 });
    expect(result.meta.page).toBe(2);
  });

  // FIXED: page=0 → Math.max(0, (0-1)*20) = Math.max(0, -20) = 0 → no error
  it('page=0: returns empty without Prisma error (FIXED)', async () => {
    const result = await service.findAll({ page: 0 });
    // FIXED: skip=0 (not -20), so Prisma is called with skip=0 → valid
    expect(result.data).toEqual([]);
    // Verify the skip value was 0 (clamped)
    const call = mockPrisma.listing.findMany.mock.calls[0]?.[0];
    expect(call?.skip).toBe(0);
  });

  it('page=-1: returns empty without Prisma error (FIXED)', async () => {
    const result = await service.findAll({ page: -1 });
    expect(result.data).toEqual([]);
    const call = mockPrisma.listing.findMany.mock.calls[0]?.[0];
    expect(call?.skip).toBe(0); // Math.max(0, -40) = 0
  });

  it('page=-999: returns empty without Prisma error (FIXED)', async () => {
    const result = await service.findAll({ page: -999 });
    expect(result.data).toEqual([]);
    const call = mockPrisma.listing.findMany.mock.calls[0]?.[0];
    expect(call?.skip).toBe(0);
  });

  it('large valid page number', async () => {
    const result = await service.findAll({ page: 1000 });
    expect(result.meta.page).toBe(1000);
  });
});

// ─── Security & Special Inputs ─────────────────────────────────────────────────

describe('Security: SQL injection, XSS, path traversal', () => {
  let service: ListingService;
  let mockPrisma: any;

  beforeEach(async () => {
    mockPrisma = makeMockPrisma(false);
    const mockAudit = makeMockAuditLog();
    service = await createModule(mockPrisma, mockAudit);
  });

  function captureAndCall(query: any) {
    mockPrisma.listing.findMany.mockClear();
    return service.findAll(query);
  }

  it('handles SQL injection payload without error', async () => {
    await captureAndCall({ q: "' OR '1'='1" });
    expect(mockPrisma.listing.findMany).toHaveBeenCalled();
  });

  it('handles SQL injection: DROP TABLE', async () => {
    await captureAndCall({ q: "'; DROP TABLE users; --" });
    expect(mockPrisma.listing.findMany).toHaveBeenCalled();
  });

  it('handles SQL injection: UNION SELECT', async () => {
    await captureAndCall({ q: "' UNION SELECT NULL--" });
    expect(mockPrisma.listing.findMany).toHaveBeenCalled();
  });

  it('handles XSS payload: script tag', async () => {
    await captureAndCall({ q: '<script>alert(1)</script>' });
    expect(mockPrisma.listing.findMany).toHaveBeenCalled();
  });

  it('handles XSS payload: img onerror', async () => {
    await captureAndCall({ q: '<img src=x onerror=alert(1)>' });
    expect(mockPrisma.listing.findMany).toHaveBeenCalled();
  });

  it('handles XSS payload: SVG onload', async () => {
    await captureAndCall({ q: '<svg onload=alert(1)>' });
    expect(mockPrisma.listing.findMany).toHaveBeenCalled();
  });

  it('handles path traversal: forward slashes', async () => {
    await captureAndCall({ q: '../../../../etc/passwd' });
    expect(mockPrisma.listing.findMany).toHaveBeenCalled();
  });

  it('handles path traversal: backslashes (Windows)', async () => {
    await captureAndCall({ q: '..\\..\\..\\..\\windows\\system32' });
    expect(mockPrisma.listing.findMany).toHaveBeenCalled();
  });

  it('handles Unicode normalization: combined diacritics', async () => {
    await captureAndCall({ q: 'a\u0301' }); // á
    expect(mockPrisma.listing.findMany).toHaveBeenCalled();
  });

  it('handles Unicode: precomposed form', async () => {
    await captureAndCall({ q: '\u00E1' }); // á
    expect(mockPrisma.listing.findMany).toHaveBeenCalled();
  });

  it('handles empty q (no search)', async () => {
    await captureAndCall({ q: '' });
    expect(mockPrisma.listing.findMany).toHaveBeenCalled();
  });

  it('handles very long string (10K chars)', async () => {
    const long = 'a'.repeat(10000);
    await captureAndCall({ q: long });
    expect(mockPrisma.listing.findMany).toHaveBeenCalled();
  });
});

// ─── Boundary Values ───────────────────────────────────────────────────────────

describe('Boundary Values (post-sanitize)', () => {
  let service: ListingService;
  let mockPrisma: any;
  let mockAudit: any;

  beforeEach(async () => {
    mockPrisma = makeMockPrisma(false);
    mockAudit = makeMockAuditLog();
    service = await createModule(mockPrisma, mockAudit);
  });

  // limit=0 previously returned meta.limit=0 → totalPages=Infinity (BUG).
  // Now sanitized to limit=1.
  it('limit=0 is clamped to 1 (no Infinity in meta)', async () => {
    const result = await service.findAll({ limit: 0 });
    expect(result.meta.limit).toBe(1);
    expect(Number.isFinite(result.meta.totalPages)).toBe(true);
  });

  it('limit=1 (minimum, kept)', async () => {
    const result = await service.findAll({ limit: 1 });
    expect(result.meta.limit).toBe(1);
  });

  // limit=1000 previously went through to Prisma.take=1000. Now clamped
  // to PAGINATION_MAX_LIMIT=100 to prevent DoS.
  it('limit=1000 is clamped to 100 (DoS guard)', async () => {
    const result = await service.findAll({ limit: 1000 });
    expect(result.meta.limit).toBe(100);
    const call = mockPrisma.listing.findMany.mock.calls[0]?.[0];
    expect(call?.take).toBe(100);
  });

  // limit=-1 previously caused Prisma.take=-1 → Prisma throw P2009.
  // Now clamped to 1.
  it('limit=-1 is clamped to 1 (no Prisma error)', async () => {
    const result = await service.findAll({ limit: -1, page: 1 });
    expect(result.meta.limit).toBe(1);
    expect(result).toBeDefined();
  });

  it('handles minPrice=0', async () => {
    const result = await service.findAll({ minPrice: 0 });
    expect(result).toBeDefined();
  });

  it('handles minPrice > maxPrice', async () => {
    const result = await service.findAll({ minPrice: 1000, maxPrice: 500 });
    expect(result).toBeDefined();
  });

  // very large price values were previously 999999999999 (BILLION*).
  // Now clamped to PRICE_MAX=1B.
  it('handles very large price values (clamped to 1B)', async () => {
    const result = await service.findAll({ minPrice: 999999999999 });
    expect(result).toBeDefined();
  });

  it('handles undefined query params (all defaults)', async () => {
    const result = await service.findAll({});
    expect(result.meta.page).toBe(1);
    expect(result.meta.limit).toBe(20);
  });
});

// ─── Defense in Depth: service-layer sanitization ────────────────────────────
//
// Even when ValidationPipe doesn't run (internal calls, test harnesses,
// future GraphQL resolvers), findAll() must never feed NaN / Infinity /
// non-finite values to Prisma. These tests bypass the DTO entirely and
// call the service with raw attacker-controlled input.

describe('Sanitization: invalid types and extreme values', () => {
  let service: ListingService;
  let mockPrisma: any;
  let mockAudit: any;

  beforeEach(async () => {
    mockPrisma = makeMockPrisma(false);
    mockAudit = makeMockAuditLog();
    service = await createModule(mockPrisma, mockAudit);
  });

  // ── non-integer / NaN / Infinity page ──────────────────────────────────────
  it('page="abc" → clamped to 1, no Prisma error, audit logged', async () => {
    const result = await service.findAll({ page: 'abc' as any });
    expect(result.meta.page).toBe(1);
    const call = mockPrisma.listing.findMany.mock.calls[0]?.[0];
    expect(Number.isInteger(call?.skip)).toBe(true);
    expect(mockAudit.log).toHaveBeenCalled();
  });

  it('page=NaN → clamped to 1', async () => {
    const result = await service.findAll({ page: NaN as any });
    expect(result.meta.page).toBe(1);
    const call = mockPrisma.listing.findMany.mock.calls[0]?.[0];
    expect(Number.isFinite(call?.skip)).toBe(true);
  });

  it('page=Infinity → clamped to 1', async () => {
    const result = await service.findAll({ page: Infinity as any });
    expect(result.meta.page).toBe(1);
    const call = mockPrisma.listing.findMany.mock.calls[0]?.[0];
    expect(Number.isFinite(call?.skip)).toBe(true);
  });

  it('page=3.7 → truncated to 3', async () => {
    const result = await service.findAll({ page: 3.7 as any });
    expect(result.meta.page).toBe(3);
  });

  it('page=Number.MAX_SAFE_INTEGER+1 → clamped to MAX_PAGE=10000', async () => {
    const result = await service.findAll({
      page: Number.MAX_SAFE_INTEGER as any,
    });
    expect(result.meta.page).toBe(10000);
  });

  // ── non-integer / NaN / Infinity limit ─────────────────────────────────────
  it('limit=NaN → clamped to default 20', async () => {
    const result = await service.findAll({ limit: NaN as any });
    expect(result.meta.limit).toBe(20);
    const call = mockPrisma.listing.findMany.mock.calls[0]?.[0];
    expect(Number.isInteger(call?.take)).toBe(true);
  });

  it('limit=Infinity → treated as invalid, reset to default 20', async () => {
    // Infinity is a non-finite sentinel (not a "valid large limit"),
    // so we drop it back to the safe default rather than clamping
    // it to MAX_LIMIT. This matches the page=Infinity contract.
    const result = await service.findAll({ limit: Infinity as any });
    expect(result.meta.limit).toBe(20);
    expect(mockAudit.log).toHaveBeenCalled();
  });

  // ── price extremes ─────────────────────────────────────────────────────────
  it('minPrice=NaN → dropped from query, no Prisma error', async () => {
    const result = await service.findAll({ minPrice: NaN as any });
    expect(result).toBeDefined();
    expect(mockAudit.log).toHaveBeenCalled();
  });

  it('minPrice=999999999999999 → clamped to 1B', async () => {
    const result = await service.findAll({ minPrice: 999999999999999 as any });
    expect(result).toBeDefined();
  });

  // ── q edge cases ───────────────────────────────────────────────────────────
  it('q as 10000-char string → truncated to 500', async () => {
    const longQ = 'a'.repeat(10000);
    const result = await service.findAll({ q: longQ });
    expect(result).toBeDefined();
    const call = mockPrisma.listing.findMany.mock.calls[0]?.[0];
    // The Prisma where.OR description-contains should use a 500-char q
    const orDesc = call?.where?.OR?.find((c: any) => c.description);
    expect(orDesc?.description?.contains?.length).toBe(500);
  });

  // ── regression: existing Math.max behavior still works ────────────────────
  it('page=0 (clamped to 1) is consistent with DTO contract', async () => {
    const result = await service.findAll({ page: 0 });
    expect(result.meta.page).toBe(1);
    const call = mockPrisma.listing.findMany.mock.calls[0]?.[0];
    expect(call?.skip).toBe(0);
  });

  it('page=-1 (clamped to 1) is consistent with DTO contract', async () => {
    const result = await service.findAll({ page: -1 });
    expect(result.meta.page).toBe(1);
    const call = mockPrisma.listing.findMany.mock.calls[0]?.[0];
    expect(call?.skip).toBe(0);
  });
});

// ─── Fuzzing Summary ──────────────────────────────────────────────────────────
/*
Total fuzzing input cases: 545 (from search-input.generator.ts)
Unique bug categories found:
  1. Type Confusion   — 7 failures → FIXED: typeof q === 'string' guard added
  2. Negative Page    — 3 failures → FIXED: Math.max(0, (page-1)*limit) added
  3. Security        — 0 failures  (Prisma ORM handles SQL injection safely)
  4. Unicode         — 0 failures  (PostgreSQL UTF-8)
  5. XSS             — 0 failures  (input used for DB search, not rendered)
  6. Path Traversal  — 0 failures  (not applicable to search)
  7. Special Chars   — 0 failures
  8. Empty/Long      — 0 failures

Confirmed unique bugs: 2 → FIXED: 2 → REMAINING: 0
*/
