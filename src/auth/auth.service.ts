import * as bcrypt from 'bcrypt';
import {
  BadRequestException,
  ConflictException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';

import { PrismaService } from 'src/prisma/prisma.service';
import { RedisService } from 'src/config/redis.service';
import { RegisterDto } from './dto/register.dto';
import { AuthResponseDto, UserResponseDto } from './dto/auth-response.dto';
import { LoginDto } from './dto/login.dto';
import { ConfigService } from '@nestjs/config';
import { JwtPayload, TokenPair } from './interfaces/jwt-payload.interface';
import { v4 as uuidv4 } from 'uuid';

@Injectable()
export class AuthService {
  private readonly SALT_ROUNDS = 10;
  private readonly PASSWORD_RESET_EXPIRY = 3600000; // 1 hour in millisecond

  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private configService: ConfigService,
    private redisService: RedisService,
  ) {}

  /**
   * Register a new user
   */
  async register(registerDto: RegisterDto): Promise<AuthResponseDto> {
    const { name, email, password } = registerDto;

    // check if user already exists
    const existingUser = await this.prisma.user.findUnique({
      where: {
        email: email.toLowerCase(),
      },
    });

    if (existingUser) {
      throw new ConflictException('User with this email already exists');
    }

    // hash password
    const hashedPassword = await bcrypt.hash(password, this.SALT_ROUNDS);

    // create user
    const user = await this.prisma.user.create({
      data: {
        name,
        email: email.toLowerCase(),
        password: hashedPassword,
      },
      select: {
        id: true,
        name: true,
        email: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    // generate token
    const tokens = await this.generateToken(user.id, user.email);

    // store refresh token in redis
    await this.storeRefreshToken(user.id, tokens.refreshToken);

    return {
      user: this.sanitizeUser(user),
      tokens,
    };
  }

  /**
   * Login user with email and password
   */

  async login(loginDto: LoginDto, ip: string): Promise<AuthResponseDto> {
    const { email, password } = loginDto;

    // check rate limit
    const attempts = await this.redisService.getLoginAttempts(ip);
    const maxAttempts = this.configService.get<number>('rateLimit.max', 5);

    if (attempts >= maxAttempts) {
      throw new UnauthorizedException(
        'Too many login attempts. Please try again later.',
      );
    }

    // find user by email
    const user = await this.prisma.user.findUnique({
      where: {
        email: email.toLowerCase(),
      },
    });

    if (!user) {
      await this.redisService.incrementLoginAttempts(ip);
      throw new UnauthorizedException('Invalid email or password');
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      await this.redisService.incrementLoginAttempts(ip);
      throw new UnauthorizedException('Invalid email or password');
    }

    // Reset login attempts on successful login
    await this.redisService.resetLoginAttempts(ip);

    // Generate tokens
    const tokens = await this.generateToken(user.id, user.email);

    // Store refresh token in Redis
    await this.storeRefreshToken(user.id, tokens.refreshToken);

    return {
      user: this.sanitizeUser(user),
      tokens,
    };
  }

  /**
   * Refresh access token
   */
  async refreshToken(userId: string, refreshToken: string): Promise<TokenPair> {
    // Verify refresh token
    const storedToken = await this.redisService.getRefreshToken(userId);

    if (!storedToken || storedToken !== refreshToken) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    // Get User
    const user = await this.prisma.user.findUnique({
      where: {
        id: userId,
      },
    });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    // Blacklist old refresh token
    await this.blacklistToken(refreshToken, '7d'); // 7 days

    // Generate new tokens
    const tokens = await this.generateToken(user.id, user.email);

    // Store new refresh token
    await this.storeRefreshToken(user.id, tokens.refreshToken);

    return tokens;
  }

  /**
   * Logout user - invalidate tokens
   */

  async logout(userId: string, accessToken: string): Promise<void> {
    // Delete refresh token from Redis
    await this.redisService.deleteRefreshToken(userId);

    // Blacklist access token
    await this.blacklistToken(accessToken, '15m'); // 24 hours
  }

  /**
   * Request password reset - send email with reset token
   */

  async requestPasswordReset(email: string): Promise<{ message: string }> {
    const user = await this.prisma.user.findUnique({
      where: { email: email.toLowerCase() },
    });

    if (!user) {
      return {
        message:
          'If the email exists, a password reset link has been sent to your email.',
      };
    }
    // Generate reset token
    const resetToken = uuidv4();

    // Store reset token in Redis with expiration (1 hour)
    await this.redisService.setPasswordResetToken(
      user.email,
      resetToken,
      this.PASSWORD_RESET_EXPIRY,
    );

    const resetExpires = new Date(
      Date.now() + this.PASSWORD_RESET_EXPIRY * 1000,
    );

    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        passwordResetToken: resetToken,
        passwordResetExpires: resetExpires,
      },
    });

    // TODO: Send email with reset token
    // For now, we'll just log it (in production, use a proper email service)
    console.log(`Password reset token for ${email}: ${resetToken}`);
    console.log(
      `Reset link: http://localhost:3000/auth/reset-password/${resetToken}`,
    );

    return {
      message: 'If the email exists, a password reset link has been sent.',
    };
  }

  /**
   * Reset password using token
   */

  async resetPassword(
    token: string,
    newPassword: string,
  ): Promise<{ message: string }> {
    // Find user by reset token
    const user = await this.prisma.user.findFirst({
      where: {
        passwordResetToken: token,
        passwordResetExpires: {
          gte: new Date(),
        },
      },
    });

    if (!user) {
      throw new BadRequestException('Invalid or expired reset token');
    }

    // verify token
    const redisToken = await this.redisService.getPasswordResetToken(
      user.email,
    );

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, this.SALT_ROUNDS);

    // Update password and clear reset token
    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        password: hashedPassword,
        passwordResetToken: null,
        passwordResetExpires: null,
      },
    });

    // Delete the token from Redis
    await this.redisService.deletePasswordResetToken(user.email);

    return {
      message:
        'Password has been reset successfully. Please login with your new password.',
    };
  }

  /**
   * Get user by ID with authorization
   */
  async getUserById(
    userId: string,
    requestingUserId: string,
  ): Promise<UserResponseDto> {
    if (userId !== requestingUserId) {
      throw new UnauthorizedException(
        'You are not authorized to access this user data',
      );
    }

    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        email: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return this.sanitizeUser(user);
  }

  /**
   * Get current user profile
   */
  async getMe(userId: string): Promise<UserResponseDto> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        email: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return this.sanitizeUser(user);
  }

  /**
   * Generate JWT access and refresh tokens
   */
  private async generateToken(
    userId: string,
    email: string,
  ): Promise<TokenPair> {
    const payload: JwtPayload = {
      sub: userId,
      email,
    };

    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(payload, {
        secret: this.configService.get('jwt.access.secret') as string,
        expiresIn: this.configService.get('jwt.access.expiresIn') as any,
      }),
      this.jwtService.signAsync(payload, {
        secret: this.configService.get('jwt.refresh.secret') as string,
        expiresIn: this.configService.get('jwt.refresh.expiresIn') as any,
      }),
    ]);

    return {
      accessToken,
      refreshToken,
    };
  }

  /**
   * Store refresh token in Redis
   */
  private async storeRefreshToken(
    userId: string,
    refreshToken: string,
  ): Promise<void> {
    const expiresIn = this.parseExpiration(
      this.configService.get<string>('jwt.refresh.expiresIn') as string,
    );
    await this.redisService.setRefreshToken(userId, refreshToken, expiresIn);
  }

  /**
   * Blacklist token in Redis
   */
  private async blacklistToken(
    token: string,
    expiresIn: string,
  ): Promise<void> {
    const seconds = this.parseExpiration(expiresIn);
    await this.redisService.blacklistToken(token, seconds);
  }

  /**
   * Parse expiration string to seconds
   */

  private parseExpiration(expiration: string): number {
    const unit = expiration.slice(-1);
    const value = parseInt(expiration.slice(0, -1), 10);

    switch (unit) {
      case 's':
        return value;
      case 'm':
        return value * 60;
      case 'h':
        return value * 3600;
      case 'd':
        return value * 86400;
      default:
        return 900; // Default 15 minutes
    }
  }

  /**
   * Sanitize user object - remove sensitive data
   */
  private sanitizeUser(user: any): UserResponseDto {
    const {
      password,
      refreshToken,
      passwordResetToken,
      passwordResetExpires,
      ...sanitized
    } = user;

    return sanitized;
  }

  /**
   * Verify password strength (additional validation)
   */
  private isPasswordStrong(password: string): boolean {
    const minLength = 8;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumber = /\d/.test(password);
    const hasSpecialChar = /[@$!%*?&]/.test(password);

    return (
      password.length >= minLength &&
      hasUpperCase &&
      hasLowerCase &&
      hasNumber &&
      hasSpecialChar
    );
  }
}
