import {
  Injectable,
  NotFoundException,
  ForbiddenException,
  BadRequestException,
  ConflictException,
} from '@nestjs/common';
import { PrismaService } from 'src/common/prisma/prisma.service';
import { AuditLogService, AuditAction } from 'src/common/services/audit-log.service';
import {
  PAGINATION_MAX_PAGE,
  PAGINATION_MAX_LIMIT,
} from 'src/common/dto/pagination.dto';
import { CreateListingDto, UpdateListingDto, SearchListingDto } from '../dto';
import { ListingStatus, BookCondition } from '@prisma/client';
import { Prisma } from '@prisma/client';

const PRICE_MAX = 1_000_000_000;

/**
 * Returns a sanitized copy of the query that is guaranteed to be
 * safe to pass straight to Prisma. This is the service-layer
 * counterpart of the DTO @Min/@Max validators, and runs even when
 * findAll() is called internally (e.g. from findMyListings) or
 * with an attacker-controlled DTO that bypassed the HTTP pipe.
 *
 * Invalid integer / range values are clamped rather than thrown,
 * because listing search is a read-only operation and 400-ing on
 * a single bad filter would defeat the user's pagination
 * navigation. The original (invalid) inputs are reported via
 * audit-log so the security team can detect probing.
 */
function sanitizeQuery(
  q: SearchListingDto,
  audit: AuditLogService,
): SearchListingDto {
  const issues: string[] = [];

  // ---- page ----
  let page = q.page;
  if (page === undefined || page === null || !Number.isFinite(page)) {
    page = 1;
    issues.push('page:invalid');
  } else if (!Number.isInteger(page)) {
    page = Math.trunc(page);
    issues.push('page:not-int');
  } else if (page < 1) {
    page = 1;
    issues.push('page:clamped-to-1');
  } else if (page > PAGINATION_MAX_PAGE) {
    page = PAGINATION_MAX_PAGE;
    issues.push(`page:clamped-to-${PAGINATION_MAX_PAGE}`);
  }

  // ---- limit ----
  let limit = q.limit;
  if (limit === undefined || limit === null || !Number.isFinite(limit)) {
    limit = 20;
    issues.push('limit:invalid');
  } else if (!Number.isInteger(limit)) {
    limit = Math.trunc(limit);
    issues.push('limit:not-int');
  } else if (limit < 1) {
    limit = 1;
    issues.push('limit:clamped-to-1');
  } else if (limit > PAGINATION_MAX_LIMIT) {
    limit = PAGINATION_MAX_LIMIT;
    issues.push(`limit:clamped-to-${PAGINATION_MAX_LIMIT}`);
  }

  // ---- q (string) ----
  let safeQ: string | undefined = q.q;
  if (safeQ !== undefined && typeof safeQ !== 'string') {
    safeQ = undefined;
    issues.push('q:dropped-non-string');
  }
  if (typeof safeQ === 'string' && safeQ.length > 500) {
    safeQ = safeQ.slice(0, 500);
    issues.push('q:truncated-500');
  }

  // ---- price range ----
  const minPrice =
    q.minPrice !== undefined && Number.isFinite(q.minPrice)
      ? Math.min(PRICE_MAX, Math.max(0, q.minPrice))
      : undefined;
  const maxPrice =
    q.maxPrice !== undefined && Number.isFinite(q.maxPrice)
      ? Math.min(PRICE_MAX, Math.max(0, q.maxPrice))
      : undefined;
  if (q.minPrice !== undefined && !Number.isFinite(q.minPrice)) {
    issues.push('minPrice:dropped');
  }
  if (q.maxPrice !== undefined && !Number.isFinite(q.maxPrice)) {
    issues.push('maxPrice:dropped');
  }

  // ---- audit log the sanitization (fire-and-forget) ----
  if (issues.length > 0) {
    void audit
      .log({
        action: AuditAction.SUSPICIOUS_INPUT,
        entityType: 'Listing',
        entityId: 'search',
        newData: { issues, raw: q },
      })
      .catch(() => {
        /* never let audit failure break the request */
      });
  }

  return {
    ...q,
    page,
    limit,
    q: safeQ,
    minPrice,
    maxPrice,
  };
}

@Injectable()
export class ListingService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly auditLog: AuditLogService,
  ) {}

  async create(dto: CreateListingDto, sellerId: number) {
    // Validate book exists
    const book = await this.prisma.book.findUnique({
      where: { id: dto.bookId },
    });
    if (!book || book.deletedAt) {
      throw new NotFoundException('Book not found');
    }

    // Validate course exists if provided
    if (dto.courseId) {
      const course = await this.prisma.course.findUnique({
        where: { id: dto.courseId },
      });
      if (!course) {
        throw new NotFoundException('Course not found');
      }
    }

    // Create listing with APPROVED status - no need for approval
    const now = new Date();
    const listing = await this.prisma.listing.create({
      data: {
        bookId: dto.bookId,
        sellerId,
        courseId: dto.courseId,
        price: dto.price,
        quantity: dto.quantity,
        condition: dto.condition,
        description: dto.description,
        location: dto.location,
        shippingOption: dto.shippingOption,
        status: ListingStatus.APPROVED, // Auto-approve - published immediately
        publishedAt: now,
        reviewedAt: now,
        reviewerId: sellerId, // Self-approved
      },
      include: {
        book: {
          include: {
            major: { include: { university: true } },
            category: true,
          },
        },
        seller: {
          select: { id: true, fullName: true, email: true },
        },
        images: {
          orderBy: [{ isPrimary: 'desc' }, { order: 'asc' }],
        },
      },
    });

    // Add images if provided
    if (dto.imageUrls && dto.imageUrls.length > 0) {
      await this.prisma.listingImage.createMany({
        data: dto.imageUrls.map((url, index) => ({
          listingId: listing.id,
          url,
          isPrimary: index === 0,
          order: index,
        })),
      });
    }

    // Log audit
    await this.auditLog.log({
      userId: sellerId,
      action: AuditAction.LISTING_CREATED,
      entityType: 'Listing',
      entityId: listing.id.toString(),
      newData: {
        bookId: dto.bookId,
        price: dto.price,
        quantity: dto.quantity,
        condition: dto.condition,
      },
    });

    // Fetch with images
    return this.findOne(listing.id, sellerId);
  }

  async findAll(query: SearchListingDto, userId?: number, userRoles?: string[]) {
    // Defense in depth: sanitize at the service layer even if the
    // DTO ValidationPipe didn't run (internal call, test, future
    // GraphQL resolver, etc.). Any clamped / dropped values are
    // recorded via audit log as SUSPICIOUS_INPUT.
    const safe = sanitizeQuery(query, this.auditLog);
    const {
      page = 1,
      limit = 20,
      sortBy = 'createdAt',
      sortOrder = 'desc',
      q,
      universityId,
      majorId,
      courseId,
      categoryId,
      condition,
      status,
      minPrice,
      maxPrice,
      approvedOnly = true,
    } = safe;

    const where: Prisma.ListingWhereInput = {
      deletedAt: null,
    };

    // Non-authenticated users or non-staff can only see APPROVED listings
    if (approvedOnly && !userId) {
      where.status = ListingStatus.APPROVED;
    } else if (approvedOnly && userId && !this.isStaff(userRoles)) {
      where.status = ListingStatus.APPROVED;
    }

    // Apply filters
    if (status && this.isStaff(userRoles)) {
      where.status = status;
    }

    // Full-text search — guard against non-string q (type confusion bug)
    if (q && typeof q === 'string') {
      where.OR = [
        { book: { title: { contains: q, mode: 'insensitive' } } },
        { book: { author: { contains: q, mode: 'insensitive' } } },
        { book: { isbn: { contains: q, mode: 'insensitive' } } },
        { description: { contains: q, mode: 'insensitive' } },
      ];
    }

    if (universityId) {
      if (!where.book) where.book = {};
      (where.book as any).major = { universityId };
    }
    if (majorId) {
      if (!where.book) where.book = {};
      (where.book as any).majorId = majorId;
    }
    if (courseId) {
      where.courseId = courseId;
    }
    if (categoryId) {
      if (!where.book) where.book = {};
      (where.book as any).categoryId = categoryId;
    }
    if (condition) {
      where.condition = condition;
    }
    if (minPrice !== undefined) {
      where.price = { gte: minPrice };
    }
    if (maxPrice !== undefined) {
      if (where.price && typeof where.price === 'object') {
        where.price = { ...where.price, lte: maxPrice };
      } else {
        where.price = { lte: maxPrice };
      }
    }

    // Map sortBy to valid fields
    const validSortFields = ['createdAt', 'price', 'updatedAt'];
    const actualSortBy = validSortFields.includes(sortBy) ? sortBy : 'createdAt';

    const [data, total] = await Promise.all([
      this.prisma.listing.findMany({
        where,
        // safe.page is already a finite int in [1, MAX_PAGE],
        // safe.limit is a finite int in [1, MAX_LIMIT], so the
        // product is always a non-negative integer < Number.MAX_SAFE_INTEGER.
        skip: (safe.page! - 1) * safe.limit!,
        take: safe.limit!,
        orderBy: { [actualSortBy]: sortOrder },
        include: {
          book: {
            include: {
              major: { include: { university: true } },
              category: true,
            },
          },
          seller: {
            select: { id: true, fullName: true },
          },
          images: {
            where: { isPrimary: true },
            take: 1,
          },
          _count: {
            select: { favorites: true },
          },
        },
      }),
      this.prisma.listing.count({ where }),
    ]);

    return {
      data,
      meta: {
        total,
        page: safe.page!,
        limit: safe.limit!,
        // safe.limit >= 1 → no division by zero
        totalPages: Math.ceil(total / safe.limit!),
        hasNext: safe.page! < Math.ceil(total / safe.limit!),
        hasPrev: safe.page! > 1,
      },
    };
  }

  async findOne(id: number, userId?: number, userRoles?: string[]) {
    const listing = await this.prisma.listing.findUnique({
      where: { id },
      include: {
        book: {
          include: {
            major: { include: { university: true } },
            category: true,
          },
        },
        seller: {
          select: { id: true, fullName: true, email: true },
        },
        course: true,
        images: {
          orderBy: [{ isPrimary: 'desc' }, { order: 'asc' }],
        },
        _count: {
          select: { favorites: true },
        },
      },
    });

    if (!listing || listing.deletedAt) {
      throw new NotFoundException('Listing not found');
    }

    // Only APPROVED listings are public
    if (listing.status !== ListingStatus.APPROVED) {
      // Owner or staff can view non-approved listings
      if (!userId || (!this.isOwner(listing.sellerId, userId) && !this.isStaff(userRoles))) {
        throw new NotFoundException('Listing not found');
      }
    }

    return listing;
  }

  async findMyListings(userId: number, query: SearchListingDto) {
    return this.findAll({ ...query, approvedOnly: false }, userId, ['SELLER']);
  }

  async update(id: number, dto: UpdateListingDto, userId: number, userRoles: string[]) {
    const listing = await this.prisma.listing.findUnique({
      where: { id },
    });

    if (!listing || listing.deletedAt) {
      throw new NotFoundException('Listing not found');
    }

    // Rule 1: Only owner can edit their listing
    if (!this.isOwner(listing.sellerId, userId)) {
      throw new ForbiddenException('You can only edit your own listings');
    }

    // Rule 7: Can only edit DRAFT, REJECTED, or APPROVED listings (not SOLD)
    if (listing.status === ListingStatus.SOLD) {
      throw new BadRequestException('Cannot edit sold listings');
    }

    // Prepare update data
    const updateData: Prisma.ListingUpdateInput = {};
    if (dto.price !== undefined) updateData.price = dto.price;
    if (dto.quantity !== undefined) updateData.quantity = dto.quantity;
    if (dto.condition !== undefined) updateData.condition = dto.condition;
    if (dto.description !== undefined) updateData.description = dto.description;
    if (dto.location !== undefined) updateData.location = dto.location;
    if (dto.shippingOption !== undefined) updateData.shippingOption = dto.shippingOption;
    if (dto.courseId !== undefined) {
      updateData.course = { connect: { id: dto.courseId } };
    }

    const updatedListing = await this.prisma.listing.update({
      where: { id },
      data: updateData,
    });

    // Update images if provided
    if (dto.imageUrls !== undefined) {
      await this.prisma.listingImage.deleteMany({ where: { listingId: id } });
      if (dto.imageUrls.length > 0) {
        await this.prisma.listingImage.createMany({
          data: dto.imageUrls.map((url, index) => ({
            listingId: id,
            url,
            isPrimary: index === 0,
            order: index,
          })),
        });
      }
    }

    // Log audit
    await this.auditLog.log({
      userId,
      action: AuditAction.LISTING_UPDATED,
      entityType: 'Listing',
      entityId: id.toString(),
      oldData: {
        price: listing.price.toString(),
        quantity: listing.quantity,
        condition: listing.condition,
      },
      newData: {
        price: dto.price?.toString() || listing.price.toString(),
        quantity: dto.quantity ?? listing.quantity,
        condition: dto.condition || listing.condition,
      },
    });

    return this.findOne(id, userId, userRoles);
  }

  async remove(id: number, userId: number, userRoles: string[]) {
    const listing = await this.prisma.listing.findUnique({
      where: { id },
    });

    if (!listing || listing.deletedAt) {
      throw new NotFoundException('Listing not found');
    }

    // Rule 1 & 8: Owner or Admin can delete
    if (!this.isOwner(listing.sellerId, userId) && !this.isAdmin(userRoles)) {
      throw new ForbiddenException('You can only delete your own listings');
    }

    // Soft delete
    await this.prisma.listing.update({
      where: { id },
      data: { deletedAt: new Date() },
    });

    // Log audit
    await this.auditLog.log({
      userId,
      action: AuditAction.LISTING_DELETED,
      entityType: 'Listing',
      entityId: id.toString(),
      oldData: { status: listing.status },
    });

    return { success: true, message: 'Listing deleted successfully' };
  }

  async submit(id: number, userId: number) {
    const listing = await this.prisma.listing.findUnique({
      where: { id },
    });

    if (!listing || listing.deletedAt) {
      throw new NotFoundException('Listing not found');
    }

    // Rule 1: Only owner can submit
    if (!this.isOwner(listing.sellerId, userId)) {
      throw new ForbiddenException('You can only submit your own listings');
    }

    // Can only submit DRAFT or REJECTED listings
    if (listing.status !== ListingStatus.DRAFT && listing.status !== ListingStatus.REJECTED) {
      throw new BadRequestException('Can only submit DRAFT or REJECTED listings');
    }

    // Update status to PENDING_REVIEW
    const updatedListing = await this.prisma.listing.update({
      where: { id },
      data: {
        status: ListingStatus.PENDING_REVIEW,
        rejectionReason: null, // Clear previous rejection reason
      },
    });

    // Log audit
    await this.auditLog.log({
      userId,
      action: AuditAction.LISTING_SUBMITTED,
      entityType: 'Listing',
      entityId: id.toString(),
      oldData: { status: listing.status },
      newData: { status: ListingStatus.PENDING_REVIEW },
    });

    return updatedListing;
  }

  async approve(id: number, reviewerId: number) {
    const listing = await this.prisma.listing.findUnique({
      where: { id },
    });

    if (!listing || listing.deletedAt) {
      throw new NotFoundException('Listing not found');
    }

    if (listing.status !== ListingStatus.PENDING_REVIEW) {
      throw new BadRequestException('Can only approve PENDING_REVIEW listings');
    }

    const updatedListing = await this.prisma.listing.update({
      where: { id },
      data: {
        status: ListingStatus.APPROVED,
        reviewerId,
        reviewedAt: new Date(),
        publishedAt: new Date(),
      },
    });

    // Log audit
    await this.auditLog.log({
      userId: reviewerId,
      action: AuditAction.LISTING_APPROVED,
      entityType: 'Listing',
      entityId: id.toString(),
      oldData: { status: listing.status },
      newData: { status: ListingStatus.APPROVED },
    });

    return updatedListing;
  }

  async reject(id: number, reviewerId: number, rejectionReason: string) {
    if (!rejectionReason || rejectionReason.trim() === '') {
      throw new BadRequestException('Rejection reason is required');
    }

    const listing = await this.prisma.listing.findUnique({
      where: { id },
    });

    if (!listing || listing.deletedAt) {
      throw new NotFoundException('Listing not found');
    }

    if (listing.status !== ListingStatus.PENDING_REVIEW) {
      throw new BadRequestException('Can only reject PENDING_REVIEW listings');
    }

    const updatedListing = await this.prisma.listing.update({
      where: { id },
      data: {
        status: ListingStatus.REJECTED,
        reviewerId,
        reviewedAt: new Date(),
        rejectionReason,
      },
    });

    // Log audit
    await this.auditLog.log({
      userId: reviewerId,
      action: AuditAction.LISTING_REJECTED,
      entityType: 'Listing',
      entityId: id.toString(),
      oldData: { status: listing.status },
      newData: { status: ListingStatus.REJECTED, rejectionReason },
    });

    return updatedListing;
  }

  async hide(id: number, userId: number, userRoles: string[]) {
    const listing = await this.prisma.listing.findUnique({
      where: { id },
    });

    if (!listing || listing.deletedAt) {
      throw new NotFoundException('Listing not found');
    }

    // Only owner or admin can hide
    if (!this.isOwner(listing.sellerId, userId) && !this.isAdmin(userRoles)) {
      throw new ForbiddenException('You can only hide your own listings');
    }

    if (listing.status !== ListingStatus.APPROVED) {
      throw new BadRequestException('Can only hide APPROVED listings');
    }

    const updatedListing = await this.prisma.listing.update({
      where: { id },
      data: {
        status: ListingStatus.HIDDEN,
      },
    });

    // Log audit
    await this.auditLog.log({
      userId,
      action: AuditAction.LISTING_HIDDEN,
      entityType: 'Listing',
      entityId: id.toString(),
      oldData: { status: listing.status },
      newData: { status: ListingStatus.HIDDEN },
    });

    return updatedListing;
  }

  // Helper methods
  private isOwner(sellerId: number, userId: number): boolean {
    return sellerId === userId;
  }

  private isStaff(roles?: string[]): boolean {
    if (!roles) return false;
    return roles.some(role => role === 'ADMIN' || role === 'MODERATOR');
  }

  private isAdmin(roles?: string[]): boolean {
    if (!roles) return false;
    return roles.some(role => role === 'ADMIN');
  }
}
