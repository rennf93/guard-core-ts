import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'text-summary'],
      include: ['src/**/*.ts'],
      exclude: [
        'src/index.ts',
        'src/**/index.ts',
        'src/protocols/**',
        'src/handlers/registry.ts',
      ],
      thresholds: {
        lines: 100,
        functions: 99,
        branches: 96,
        statements: 100,
      },
    },
  },
});
