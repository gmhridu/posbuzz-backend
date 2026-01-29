import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  HttpCode,
  HttpStatus,
  Ip,
  UseGuards,
  Req,
  UnauthorizedException,
} from '@nestjs/common';
import type { Request } from 'express';
import { AuthService } from './auth.service';
import {
  ApiBearerAuth,
  ApiBody,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { Public } from './decorators/public.decorator';
import {
  AuthResponseDto,
  AuthTokensDto,
  UserResponseDto,
} from './dto/auth-response.dto';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { JwtRefreshGuard } from './guards/jwt-refresh.guard';
import { GetUser } from './decorators/get-user-decorator';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { PasswordResetRequestDto } from './dto/password-reset-request.dto';
import { PasswordResetDto } from './dto/password-reset.dto';

@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Public()
  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: 'Register a new user',
    description:
      'Creates a new user account with email and password. Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character.',
  })
  @ApiResponse({
    status: HttpStatus.CREATED,
    description: 'User registered successfully',
    type: AuthResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Invalid input data',
  })
  @ApiBody({
    type: RegisterDto,
  })
  async register(@Body() registerDto: RegisterDto): Promise<AuthResponseDto> {
    return this.authService.register(registerDto);
  }

  @Public()
  @Post('login')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Login user',
    description:
      'Authenticates user with email and password. Rate limited to 5 attempts per minute per IP',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'User logged in successfully',
    type: AuthResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Invalid credentials or too many login attempts',
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Invalid input data',
  })
  @ApiBody({ type: LoginDto })
  async login(
    @Body() loginDto: LoginDto,
    @Ip() ip: string,
  ): Promise<AuthResponseDto> {
    return this.authService.login(loginDto, ip);
  }

  @Public()
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  @UseGuards(JwtRefreshGuard)
  @ApiOperation({
    summary: 'Refresh access token',
    description:
      'Generates a new access token using a valid refresh token. Returns new access token and refresh token.',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Tokens successfully refreshed',
    type: AuthResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Invalid refresh token',
  })
  @ApiBody({ type: RefreshTokenDto })
  async refreshTokens(
    @GetUser('id') userId: string,
    @Body() refreshTokenDto: RefreshTokenDto,
  ): Promise<AuthTokensDto> {
    return this.authService.refreshToken(userId, refreshTokenDto.refreshToken);
  }

  @Post('logout')
  @HttpCode(HttpStatus.OK)
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Logout user',
    description:
      'Invalidates the refresh token and blacklists the access token. User must login again.',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'User logged out successfully',
    schema: {
      type: 'object',
      properties: {
        message: {
          type: 'string',
          example: 'User logged out successfully',
        },
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Invalid or expired token',
  })
  async logout(
    @GetUser('id') userId: string,
    @Req() req: Request,
  ): Promise<{ message: string }> {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
      throw new UnauthorizedException('Authorization token missing');
    }

    const token = authHeader.replace('Bearer ', '');
    await this.authService.logout(userId, token);
    return { message: 'User logged out successfully' };
  }

  @Get('me')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Get current user profile',
    description: 'Returns the profile of the currently authenticated user.',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'User profile retrieved successfully',
    type: UserResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Invalid or expired token',
  })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: 'User not found',
  })
  async getMe(@GetUser('id') userId: string): Promise<UserResponseDto> {
    return this.authService.getMe(userId);
  }

  @Get('user/:id')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Get user by ID',
    description:
      'Returns user information by ID. Users can only access their own data.',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'User information',
    type: UserResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description:
      'Invalid or missing authentication token, or unauthorized access',
  })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: 'User not found',
  })
  async getUserById(
    @Param('id') userId: string,
    @GetUser('id') requestingUserId: string,
  ): Promise<UserResponseDto> {
    return this.authService.getUserById(userId, requestingUserId);
  }

  @Public()
  @Post('password-reset/request')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Request password reset',
    description:
      'Sends a password reset token to the user email. Token expires in 1 hour.',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Password reset email sent (if email exists)',
    schema: {
      type: 'object',
      properties: {
        message: {
          type: 'string',
          example: 'If the email exists, a password reset link has been sent.',
        },
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Invalid email format',
  })
  @ApiBody({ type: PasswordResetRequestDto })
  async requestPasswordReset(
    @Body() passwordRequestDto: PasswordResetRequestDto,
  ): Promise<{ message: string }> {
    return this.authService.requestPasswordReset(passwordRequestDto.email);
  }

  @Public()
  @Post('password-reset/confirm')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Reset password with token',
    description:
      'Resets user password using the reset token received via email.',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Password successfully reset',
    schema: {
      type: 'object',
      properties: {
        message: {
          type: 'string',
          example:
            'Password has been reset successfully. Please login with your new password.',
        },
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Invalid or expired token, or password validation failed',
  })
  @ApiBody({ type: PasswordResetDto })
  async resetPassword(
    @Body() passwordResetDto: PasswordResetDto,
  ): Promise<{ message: string }> {
    return this.authService.resetPassword(
      passwordResetDto.token,
      passwordResetDto.newPassword,
    );
  }
}
