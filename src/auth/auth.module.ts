import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { RedisService } from 'src/config/redis.service';

@Module({
  controllers: [AuthController],
  providers: [AuthService, RedisService],
})
export class AuthModule {}
