import {
  Injectable,
  NotFoundException,
  OnModuleDestroy,
  OnModuleInit,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Redis from 'ioredis';

@Injectable()
export class RedisService implements OnModuleInit, OnModuleDestroy {
  private client: Redis;

  constructor(private configService: ConfigService) {}

  async onModuleInit() {
    const redisUrl = this.configService.get<string>('redis');

    if (!redisUrl) {
      throw new NotFoundException('REDIS_URL is not defined');
    }

    this.client = new Redis(redisUrl, {
      retryStrategy: (times) => {
        const delay = Math.min(times * 50, 2000);
        return delay;
      },
      maxRetriesPerRequest: 3,
    });

    this.client.on('error', (err) => {
      console.error('Redis Client error:', err);
    });

    this.client.on('connect', () => {
      console.log('Redis Client connected');
    });

    // wait until Redis is ready
    await this.client.ping();

    await this.client.set('foo', 'bar');
  }

  async onModuleDestroy() {
    await this.client.quit();
  }

  getClient(): Redis {
    return this.client;
  }

  // Token Management

  async setRefreshToken(
    userId: string,
    token: string,
    expiresIn: number,
  ): Promise<void> {
    const key = `refresh_token:${userId}`;
    await this.client.setex(key, expiresIn, token);
  }

  async getRefreshToken(userId: string): Promise<string | null> {
    const key = `refresh_token:${userId}`;
    return await this.client.get(key);
  }

  async deleteRefreshToken(userId: string): Promise<void> {
    const key = `refresh_token:${userId}`;
    await this.client.del(key);
  }

  async blacklistToken(token: string, expiresIn: number): Promise<void> {
    const key = `blacklist:${token}`;
    await this.client.setex(key, expiresIn, '1');
  }

  async isTokenBlacklisted(token: string): Promise<boolean> {
    const key = `blacklist:${token}`;

    const result = await this.client.get(key);
    return result === '1';
  }

  // Rate Limiting

  async incrementLoginAttempts(ip: string): Promise<number> {
    const key = `login_attempts:${ip}`;

    const attempts = await this.client.incr(key);

    if (attempts === 1) {
      // Set expiration only on first attempt
      const ttl = this.configService.get<number>('rateLimit.ttl') || 60;
      await this.client.expire(key, ttl);
    }

    return attempts;
  }

  async getLoginAttempts(ip: string): Promise<number> {
    const key = `login_attempts:${ip}`;
    const attempts = await this.client.get(key);
    return attempts ? parseInt(attempts, 10) : 0;
  }

  async resetLoginAttempts(ip: string): Promise<void> {
    const key = `login_attempts:${ip}`;
    await this.client.del(key);
  }

  // Password Reset Token Management
  async setPasswordResetToken(
    email: string,
    token: string,
    expiresIn: number = 3600, // 1 hour in seconds
  ): Promise<void> {
    const key = `password_reset:${email}`;
    await this.client.setex(key, expiresIn, token);
  }

  async getPasswordResetToken(email: string): Promise<string | null> {
    const key = `password_reset:${email}`;
    return await this.client.get(key);
  }

  async deletePasswordResetToken(email: string): Promise<void> {
    const key = `password_reset:${email}`;
    await this.client.del(key);
  }

  // Product caching
  async cacheProduct(products: any): Promise<void> {
    const key = `products:list`;
    await this.client.setex(key, 300, JSON.stringify(products)); // Cache for 5 minutes
  }

  async getCachedProducts(): Promise<any | null> {
    const key = `products:list`;
    const cached = await this.client.get(key);
    return cached ? JSON.parse(cached) : null;
  }

  async invalidateProductCache(): Promise<void> {
    const key = `products:list`;
    await this.client.del(key);
  }

  // Generic cache operations
  async set(key: string, value: string, expiresIn?: number): Promise<void> {
    if (expiresIn) {
      await this.client.setex(key, expiresIn, value);
    } else {
      await this.client.set(key, value);
    }
  }

  async get(key: string): Promise<string | null> {
    return await this.client.get(key);
  }

  async del(key: string): Promise<void> {
    await this.client.del(key);
  }

  async exists(key: string): Promise<boolean> {
    const result = await this.client.exists(key);

    return result === 1;
  }
}
