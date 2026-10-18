import { ApiPropertyOptional } from '@nestjs/swagger';
import { Type } from 'class-transformer';
import { IsEnum, IsInt, IsOptional, IsString, Min, Max } from 'class-validator';
import { Order } from 'src/common/enums/order.enum';

// Hard limits enforced at the DTO layer (HTTP / class-validator).
// The service layer also enforces these to defend against bypass
// (internal calls, tests, future GraphQL resolvers, etc.).
export const PAGINATION_MAX_PAGE = 10000;
export const PAGINATION_MAX_LIMIT = 100;

export class PaginationDto {
  @ApiPropertyOptional({ default: 1, minimum: 1, maximum: PAGINATION_MAX_PAGE })
  @IsOptional()
  @Type(() => Number)
  @IsInt({ message: 'page must be an integer' })
  @Min(1, { message: 'page must be >= 1' })
  @Max(PAGINATION_MAX_PAGE, { message: `page must be <= ${PAGINATION_MAX_PAGE}` })
  page?: number = 1;

  @ApiPropertyOptional({ default: 20, minimum: 1, maximum: PAGINATION_MAX_LIMIT })
  @IsOptional()
  @Type(() => Number)
  @IsInt({ message: 'limit must be an integer' })
  @Min(1, { message: 'limit must be >= 1' })
  @Max(PAGINATION_MAX_LIMIT, { message: `limit must be <= ${PAGINATION_MAX_LIMIT}` })
  limit?: number = 20;

  @ApiPropertyOptional({ default: 'createdAt' })
  @IsOptional()
  @IsString()
  sortBy?: string = 'createdAt';

  @ApiPropertyOptional({ default: Order.DESC })
  @IsOptional()
  @IsEnum(Order)
  sortOrder?: Order = Order.DESC;
}

export class PaginatedResponseDto<T> {
  data: T[];
  meta: {
    total: number;
    page: number;
    limit: number;
    totalPages: number;
    hasNext: boolean;
    hasPrev: boolean;
  };

  constructor(data: T[], total: number, page: number, limit: number) {
    this.data = data;
    const totalPages = Math.ceil(total / limit);
    this.meta = {
      total,
      page,
      limit,
      totalPages,
      hasNext: page < totalPages,
      hasPrev: page > 1,
    };
  }
}
