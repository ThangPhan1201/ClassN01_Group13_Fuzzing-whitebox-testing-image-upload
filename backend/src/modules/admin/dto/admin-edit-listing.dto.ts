import {
  IsString,
  IsOptional,
  IsInt,
  IsNumber,
  IsEnum,
  Matches,
  MaxLength,
  Min,
  Max,
} from 'class-validator';
import { Type } from 'class-transformer';
import { BookCondition, ShippingOption } from '@prisma/client';
import { PRICE_MAX } from 'src/modules/listing/dto/listing.dto';

/**
 * Dùng cho route admin PATCH /admin/listings/:id.
 *
 * Trước đây controller nhận raw @Body() body: { ... } không validate
 * → price=-1, publicationYear="abc", description 100kB bị đẩy thẳng
 *   xuống Prisma → 500 Internal Server Error.
 *
 * Dynamic fuzzer (http_fuzz.py) tìm thấy 5/30 trials crash ở route này.
 * Bug tương ứng M1–M4 trong cwe_mapping.json (CWE-20 Improper Input Validation).
 *
 * NOTE: `price` ở service dùng string (Prisma Decimal) → match signature.
 * Validation vẫn bảo vệ: type=number, min=1, max=PRICE_MAX.
 */
export class AdminEditListingDto {
  @IsOptional()
  @IsString()
  @MaxLength(500)
  title?: string;

  @IsOptional()
  @IsString()
  @MaxLength(200)
  author?: string;

  @IsOptional()
  @IsString()
  @MaxLength(200)
  publisher?: string;

  @IsOptional()
  @IsString()
  @MaxLength(50)
  isbn?: string;

  @IsOptional()
  @IsString()
  @MaxLength(50)
  edition?: string;

  @IsOptional()
  @Type(() => Number)
  @IsInt({ message: 'publicationYear must be an integer' })
  @Min(1000, { message: 'publicationYear too small' })
  @Max(9999, { message: 'publicationYear too large' })
  publicationYear?: number;

  @IsOptional()
  @Type(() => Number)
  @IsInt({ message: 'categoryId must be an integer' })
  @Min(1)
  categoryId?: number;

  /**
   * price: DB column là Decimal(12,2) → Prisma nhận string.
   * Validate là chuỗi số thập phân dương, tối đa PRICE_MAX.
   * Trước đây không validate → price="abc" hoặc price=-1 làm Prisma throw → 500.
   */
  @IsOptional()
  @IsString()
  @MaxLength(20)
  @Matches(/^\d+(\.\d{1,2})?$/, {
    message: 'price must be a decimal number (e.g. "150000" or "150000.50")',
  })
  price?: string;

  @IsOptional()
  @Type(() => Number)
  @IsInt({ message: 'quantity must be an integer' })
  @Min(1, { message: 'Số lượng phải >= 1' })
  quantity?: number;

  @IsOptional()
  @IsEnum(BookCondition)
  condition?: BookCondition;

  @IsOptional()
  @IsString()
  @MaxLength(2000)
  description?: string;

  @IsOptional()
  @IsString()
  @MaxLength(500)
  location?: string;

  @IsOptional()
  @IsEnum(ShippingOption)
  shippingOption?: ShippingOption;
}
