import {
  BadRequestException,
  Injectable,
  OnModuleDestroy,
  OnModuleInit,
} from '@nestjs/common';
import { PrismaClient } from 'prisma/generated';

@Injectable()
export class PrismaService
  extends PrismaClient
  implements OnModuleInit, OnModuleDestroy
{
  constructor() {
    super({
      log: ['error', 'warn'],
      errorFormat: 'pretty',
    });
  }

  async onModuleInit() {
    await this.$connect();
    console.log('Connected to the database');
  }

  async onModuleDestroy() {
    await this.$disconnect();
    console.log('Disconnected from the database');
  }

  async cleanDatabase() {
    if (process.env.NODE_ENV === 'production') {
      throw new BadRequestException('Cannot clean database in production');
    }
    const models = Object.keys(this).filter(
      (key) =>
        !key.startsWith('$') &&
        !key.startsWith('_') &&
        key !== 'constructor' &&
        typeof (this as any)[key] === 'object' &&
        (this as any)[key] !== null,
    );

    return Promise.all(
      models
        .map((modelKey) => {
          const model = (this as any)[modelKey];
          if (model && typeof model.deleteMany === 'function') {
            return model.deleteMany();
          }
          return null;
        })
        .filter((p) => p !== null),
    );
  }

  enableShutdownHooks(app: any) {
    process.on('beforeExit', async () => {
      await app.close();
    });
  }
}
