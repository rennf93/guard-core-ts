import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm', 'cjs'],
  dts: true,
  sourcemap: true,
  clean: true,
  target: 'es2022',
  external: ['@nestjs/common', '@nestjs/core', 'express', 'reflect-metadata', 'rxjs', '@guardcore/core'],
});
