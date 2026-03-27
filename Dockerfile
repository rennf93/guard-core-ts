FROM node:22-slim AS base

RUN corepack enable pnpm

WORKDIR /app

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml turbo.json tsconfig.base.json ./
COPY packages/ packages/

RUN pnpm install --frozen-lockfile

RUN pnpm build

CMD ["pnpm", "test"]
