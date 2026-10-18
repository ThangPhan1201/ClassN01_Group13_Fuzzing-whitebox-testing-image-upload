import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/common/prisma/prisma.service';
import { Prisma } from '@prisma/client';

export enum AuditAction {
  LISTING_CREATED = 'LISTING_CREATED',
  LISTING_UPDATED = 'LISTING_UPDATED',
  LISTING_SUBMITTED = 'LISTING_SUBMITTED',
  LISTING_APPROVED = 'LISTING_APPROVED',
  LISTING_REJECTED = 'LISTING_REJECTED',
  LISTING_HIDDEN = 'LISTING_HIDDEN',
  LISTING_DELETED = 'LISTING_DELETED',
  LISTING_VIEWED = 'LISTING_VIEWED',
  ORDER_CREATED = 'ORDER_CREATED',
  ORDER_STATUS_CHANGED = 'ORDER_STATUS_CHANGED',
  PAYMENT_COD_SUCCESS = 'PAYMENT_COD_SUCCESS',
  PAYMENT_MOCK_SUCCESS = 'PAYMENT_MOCK_SUCCESS',
  PAYMENT_MOCK_FAILED = 'PAYMENT_MOCK_FAILED',
  PAYMENT_MOCK_CANCELLED = 'PAYMENT_MOCK_CANCELLED',
  PAYMENT_REFUNDED = 'PAYMENT_REFUNDED',
  // VNPAY actions
  PAYMENT_VNPAY_PENDING = 'PAYMENT_VNPAY_PENDING',
  PAYMENT_VNPAY_SUCCESS = 'PAYMENT_VNPAY_SUCCESS',
  PAYMENT_VNPAY_FAILED = 'PAYMENT_VNPAY_FAILED',
  PAYMENT_VNPAY_CANCELLED = 'PAYMENT_VNPAY_CANCELLED',
  PAYMENT_VNPAY_IPN_RECEIVED = 'PAYMENT_VNPAY_IPN_RECEIVED',
  // Banking actions
  PAYMENT_BANKING_PENDING = 'PAYMENT_BANKING_PENDING',
  PAYMENT_CONFIRMED = 'PAYMENT_CONFIRMED',
  // Escrow actions
  ESCROW_CREATED = 'ESCROW_CREATED',
  ESCROW_DISPUTED = 'ESCROW_DISPUTED',
  ESCROW_RELEASED = 'ESCROW_RELEASED',
  ESCROW_RESOLVED_RELEASE = 'ESCROW_RESOLVED_RELEASE',
  ESCROW_RESOLVED_REFUND = 'ESCROW_RESOLVED_REFUND',
  // Review actions
  REVIEW_CREATED = 'REVIEW_CREATED',
  REVIEW_MODERATED = 'REVIEW_MODERATED',
  REVIEW_RESPONSE = 'REVIEW_RESPONSE',
  // Coupon actions
  COUPON_CREATED = 'COUPON_CREATED',
  COUPON_APPLIED = 'COUPON_APPLIED',
  COUPON_UPDATED = 'COUPON_UPDATED',
  // Admin actions
  USER_DEACTIVATED = 'USER_DEACTIVATED',
  REPORT_RESOLVED = 'REPORT_RESOLVED',
  // Security / abuse signal — used when service-layer sanitization
  // clamps / drops inputs that the DTO should have caught. If you
  // see this action, the request bypassed the ValidationPipe and
  // you should investigate the caller.
  SUSPICIOUS_INPUT = 'SUSPICIOUS_INPUT',
}

@Injectable()
export class AuditLogService {
  constructor(private readonly prisma: PrismaService) {}

  async log(params: {
    userId?: number;
    action: AuditAction;
    entityType: string;
    entityId?: string;
    oldData?: Record<string, unknown>;
    newData?: Record<string, unknown>;
    ipAddress?: string;
    userAgent?: string;
  }) {
    return this.prisma.auditLog.create({
      data: {
        userId: params.userId,
        action: params.action,
        entityType: params.entityType,
        entityId: params.entityId,
        oldData: params.oldData ? (params.oldData as Prisma.InputJsonValue) : undefined,
        newData: params.newData ? (params.newData as Prisma.InputJsonValue) : undefined,
        ipAddress: params.ipAddress,
        userAgent: params.userAgent,
      },
    });
  }
}
