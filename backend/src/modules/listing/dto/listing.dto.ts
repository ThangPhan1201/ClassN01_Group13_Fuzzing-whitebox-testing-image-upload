import {
  IsString,
  IsOptional,
  IsNumber,
  IsEnum,
  IsArray,
  MaxLength,
  Min,
  Max,
  ValidateNested,
  IsBoolean,
  IsInt,
} from 'class-validator';
import { Type } from 'class-transformer';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { BookCondition, ShippingOption, ListingStatus } from '@prisma/client';
import {
  PaginationDto,
  PAGINATION_MAX_LIMIT,
  PAGINATION_MAX_PAGE,
} from 'src/common/dto/pagination.dto';

// Max price is bounded to prevent absurd values from causing
// unnecessary scan cost on the price index.
export const PRICE_MAX = 1_000_000_000; // 1B VND

export class CreateListingDto {
  @ApiProperty({ example: 1, description: 'ID của sách' })
  @Type(() => Number)
  @IsNumber()
  bookId: number;

  @ApiPropertyOptional({ example: 1, description: 'ID của học phần (tùy chọn)' })
  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  courseId?: number;

  @ApiProperty({ example: 150000, description: 'Giá bán' })
  @Type(() => Number)
  @IsNumber()
  @Min(1, { message: 'Giá phải lớn hơn 0' })
  price: number;

  @ApiProperty({ example: 1, description: 'Số lượng', minimum: 1 })
  @Type(() => Number)
  @IsNumber()
  @Min(1, { message: 'Số lượng phải >= 1' })
  quantity: number;

  @ApiProperty({ enum: BookCondition, description: 'Tình trạng sách' })
  @IsEnum(BookCondition)
  condition: BookCondition;

  @ApiPropertyOptional({ example: 'Sách còn mới, có một số ghi chú nhỏ', description: 'Mô tả' })
  @IsOptional()
  @IsString()
  @MaxLength(2000)
  description?: string;

  @ApiPropertyOptional({ example: 'TP.HCM, Quận 10', description: 'Địa điểm' })
  @IsOptional()
  @IsString()
  @MaxLength(500)
  location?: string;

  @ApiProperty({ enum: ShippingOption, description: 'Phương thức vận chuyển' })
  @IsEnum(ShippingOption)
  shippingOption: ShippingOption;

  @ApiPropertyOptional({ example: ['url1.jpg', 'url2.png'], description: 'Danh sách URL ảnh' })
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  imageUrls?: string[];
}

export class UpdateListingDto {
  @ApiPropertyOptional({ example: 150000, description: 'Giá bán' })
  @IsOptional()
  @IsNumber()
  @Min(1, { message: 'Giá phải lớn hơn 0' })
  price?: number;

  @ApiPropertyOptional({ example: 2, description: 'Số lượng' })
  @IsOptional()
  @IsNumber()
  @Min(1, { message: 'Số lượng phải >= 1' })
  quantity?: number;

  @ApiPropertyOptional({ enum: BookCondition, description: 'Tình trạng sách' })
  @IsOptional()
  @IsEnum(BookCondition)
  condition?: BookCondition;

  @ApiPropertyOptional({ example: 'Cập nhật mô tả mới', description: 'Mô tả' })
  @IsOptional()
  @IsString()
  @MaxLength(2000)
  description?: string;

  @ApiPropertyOptional({ example: 'TP.HCM, Quận 10', description: 'Địa điểm' })
  @IsOptional()
  @IsString()
  @MaxLength(500)
  location?: string;

  @ApiPropertyOptional({ enum: ShippingOption, description: 'Phương thức vận chuyển' })
  @IsOptional()
  @IsEnum(ShippingOption)
  shippingOption?: ShippingOption;

  @ApiPropertyOptional({ example: ['url1.jpg', 'url2.png'], description: 'Danh sách URL ảnh' })
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  imageUrls?: string[];

  @ApiPropertyOptional({ example: 1, description: 'ID của học phần' })
  @IsOptional()
  @IsNumber()
  courseId?: number;
}

export class RejectListingDto {
  @ApiProperty({ example: 'Giá quá thấp so với giá thị trường', description: 'Lý do từ chối' })
  @IsString()
  @MaxLength(500)
  rejectionReason: string;
}

export class SearchListingDto extends PaginationDto {
  // Re-declare with @Type + @IsInt so that the DTO layer is robust
  // even when the inherited decorators are lost (e.g. when a global
  // ValidationPipe whitelist strips unknown properties, or when the
  // body comes from a non-Express path).
  @ApiPropertyOptional({ default: 1, minimum: 1, maximum: PAGINATION_MAX_PAGE })
  @IsOptional()
  @Type(() => Number)
  @IsInt({ message: 'page must be an integer' })
  @Min(1)
  @Max(PAGINATION_MAX_PAGE)
  page?: number = 1;

  @ApiPropertyOptional({ default: 20, minimum: 1, maximum: PAGINATION_MAX_LIMIT })
  @IsOptional()
  @Type(() => Number)
  @IsInt({ message: 'limit must be an integer' })
  @Min(1)
  @Max(PAGINATION_MAX_LIMIT)
  limit?: number = 20;

  @ApiPropertyOptional({ description: 'Tìm kiếm toàn phần' })
  @IsOptional()
  @IsString()
  q?: string;

  @ApiPropertyOptional({ example: 1, description: 'Lọc theo trường đại học' })
  @IsOptional()
  @IsNumber()
  universityId?: number;

  @ApiPropertyOptional({ example: 1, description: 'Lọc theo ngành học' })
  @IsOptional()
  @IsNumber()
  majorId?: number;

  @ApiPropertyOptional({ example: 1, description: 'Lọc theo học phần' })
  @IsOptional()
  @IsNumber()
  courseId?: number;

  @ApiPropertyOptional({ example: 1, description: 'Lọc theo danh mục' })
  @IsOptional()
  @IsNumber()
  categoryId?: number;

  @ApiPropertyOptional({ enum: BookCondition, description: 'Lọc theo tình trạng' })
  @IsOptional()
  @IsEnum(BookCondition)
  condition?: BookCondition;

  @ApiPropertyOptional({ enum: ListingStatus, description: 'Lọc theo trạng thái' })
  @IsOptional()
  @IsEnum(ListingStatus)
  status?: ListingStatus;

  @ApiPropertyOptional({ description: 'Giá từ', type: Number })
  @IsOptional()
  @Type(() => Number)
  @IsNumber({ allowNaN: false, allowInfinity: false }, { message: 'minPrice must be a finite number' })
  @Min(0)
  @Max(PRICE_MAX)
  minPrice?: number;

  @ApiPropertyOptional({ description: 'Giá đến', type: Number })
  @IsOptional()
  @Type(() => Number)
  @IsNumber({ allowNaN: false, allowInfinity: false }, { message: 'maxPrice must be a finite number' })
  @Min(0)
  @Max(PRICE_MAX)
  maxPrice?: number;

  @ApiPropertyOptional({ description: 'Chỉ hiển thị listing đã approve' })
  @IsOptional()
  @IsBoolean()
  approvedOnly?: boolean;
}
