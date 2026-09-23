import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module.js';

async function bootstrap(): Promise<void> {
  const app = await NestFactory.create(AppModule);
  const port = Number(process.env['PORT'] ?? 3000);
  await app.listen(port);
  console.log(`@guardcore/nestjs example running on port ${port}`);
}

void bootstrap();
