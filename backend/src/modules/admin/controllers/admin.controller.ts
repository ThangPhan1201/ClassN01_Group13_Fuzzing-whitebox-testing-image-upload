/**
 * ADMIN CONTROLLER
 * ================
 * 
 * Admin Dashboard và Management APIs
 * CHỈ ADMIN MỚI ĐƯỢC TRUY CẬP
 */

import {
  Controller, Get, Post, Delete, Patch, Body, Param, Query, ParseIntPipe, UseGuards,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiBearerAuth } from '@nestjs/swagger';
import { AdminService } from '../services/admin.service';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { RolesGuard } from 'src/auth/guards/roles.guard';
import { Roles } from 'src/auth/decorators/roles.decorator';
import { RoleType } from '@prisma/client';
import { CurrentUser } from 'src/auth/decorators/current-user.decorator';
import { AdminEditListingDto } from '../dto/admin-edit-listing.dto';

@ApiTags('Admin - Dashboard')
@Controller('admin')
@UseGuards(JwtAuthGuard, RolesGuard)
@ApiBearerAuth()
@Roles(RoleType.ADMIN)
export class AdminController {
  constructor(private readonly adminService: AdminService) {}

  // ======================
  // DASHBOARD STATS
  // ======================

  @Get('dashboard/stats')
  @ApiOperation({ summary: 'Lấy dashboard statistics' })
  async getDashboardStats() {
    return this.adminService.getDashboardStats();
  }

  @Get('dashboard/revenue-by-day')
  @ApiOperation({ summary: 'Doanh thu theo ngày' })
  async getRevenueByDay(@Query('days') days?: number) {
    return this.adminService.getRevenueByDay(days || 30);
  }

  @Get('dashboard/orders-by-day')
  @ApiOperation({ summary: 'Số đơn hàng theo ngày' })
  async getOrdersByDay(@Query('days') days?: number) {
    return this.adminService.getOrdersByDay(days || 30);
  }

  @Get('dashboard/user-registrations-by-day')
  @ApiOperation({ summary: 'User đăng ký theo ngày' })
  async getUserRegistrationsByDay(@Query('days') days?: number) {
    return this.adminService.getUserRegistrationsByDay(days || 30);
  }

  @Get('dashboard/listings-by-day')
  @ApiOperation({ summary: 'Listing tạo theo ngày' })
  async getListingsByDay(@Query('days') days?: number) {
    return this.adminService.getListingsByDay(days || 30);
  }

  @Get('dashboard/top-categories')
  @ApiOperation({ summary: 'Top categories' })
  async getTopCategories(@Query('limit') limit?: number) {
    return this.adminService.getTopCategories(limit || 10);
  }

  @Get('dashboard/top-courses')
  @ApiOperation({ summary: 'Top courses' })
  async getTopCourses(@Query('limit') limit?: number) {
    return this.adminService.getTopCourses(limit || 10);
  }

  // ======================
  // USER MANAGEMENT
  // ======================

  @Get('users')
  @ApiOperation({ summary: 'Lấy danh sách users' })
  async getUsers(
    @Query('page') page?: number,
    @Query('limit') limit?: number,
    @Query('search') search?: string,
  ) {
    return this.adminService.getUsers(page || 1, limit || 20, search);
  }

  @Post('users/:id/deactivate')
  @ApiOperation({ summary: 'Deactivate user (soft delete)' })
  async deactivateUser(
    @Param('id', ParseIntPipe) id: number,
    @Body() body: { reason: string },
    @CurrentUser() user: any,
  ) {
    return this.adminService.deactivateUser(id, user.id, body.reason);
  }

  // ======================
  // LISTING MANAGEMENT
  // ======================

  @Get('listings')
  @ApiOperation({ summary: 'Lấy danh sách listings' })
  async getListings(
    @Query('page') page?: number,
    @Query('limit') limit?: number,
    @Query('status') status?: string,
    @Query('search') search?: string,
  ) {
    return this.adminService.getListings(page || 1, limit || 20, status as any, search);
  }

  @Patch('listings/:id')
  @ApiOperation({ summary: 'Admin chỉnh sửa listing (bao gồm thông tin sách)' })
  async editListing(
    @Param('id', ParseIntPipe) id: number,
    @Body() body: AdminEditListingDto,
    @CurrentUser() user: any,
  ) {
    return this.adminService.editListing(id, body, user.id);
  }

  // ======================
  // ORDER MANAGEMENT
  // ======================

  @Get('orders')
  @ApiOperation({ summary: 'Lấy danh sách orders' })
  async getOrders(
    @Query('page') page?: number,
    @Query('limit') limit?: number,
    @Query('status') status?: string,
  ) {
    return this.adminService.getOrders(page || 1, limit || 20, status as any);
  }

  // ======================
  // PAYMENT MANAGEMENT
  // ======================

  @Get('payments')
  @ApiOperation({ summary: 'Lấy danh sách payments' })
  async getPayments(
    @Query('page') page?: number,
    @Query('limit') limit?: number,
    @Query('status') status?: string,
  ) {
    return this.adminService.getPayments(page || 1, limit || 20, status);
  }

  // ======================
  // REVIEW MANAGEMENT
  // ======================

  @Get('reviews')
  @ApiOperation({ summary: 'Lấy danh sách reviews' })
  async getReviews(
    @Query('page') page?: number,
    @Query('limit') limit?: number,
    @Query('status') status?: string,
  ) {
    return this.adminService.getReviews(page || 1, limit || 20, status);
  }

  // ======================
  // REPORT MANAGEMENT
  // ======================

  @Get('reports')
  @ApiOperation({ summary: 'Lấy danh sách reports' })
  async getReports(
    @Query('page') page?: number,
    @Query('limit') limit?: number,
    @Query('status') status?: string,
  ) {
    return this.adminService.getReports(page || 1, limit || 20, status);
  }

  @Post('reports/:id/resolve')
  @ApiOperation({ summary: 'Resolve report' })
  async resolveReport(
    @Param('id', ParseIntPipe) id: number,
    @Body() body: { action: 'RESOLVED' | 'DISMISSED'; note?: string },
    @CurrentUser() user: any,
  ) {
    return this.adminService.resolveReport(id, user.id, body.action, body.note);
  }
}
