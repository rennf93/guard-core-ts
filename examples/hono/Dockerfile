# Build context is the repository root (see docker-compose.yml):
#   docker build -f examples/hono/Dockerfile .
FROM node:22-alpine AS build

RUN corepack enable pnpm

WORKDIR /app

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml turbo.json tsconfig.base.json ./
COPY packages/ packages/
COPY examples/ examples/

RUN pnpm install --frozen-lockfile

RUN pnpm --filter @guardcore/core build \
  && pnpm --filter @guardcore/express build \
  && pnpm --filter @guardcore/fastify build \
  && pnpm --filter @guardcore/hono build \
  && pnpm --filter @guardcore/nestjs build

FROM node:22-alpine

RUN corepack enable pnpm

RUN addgroup -S guard && adduser -S guard -G guard

WORKDIR /app

COPY --from=build /app /app

USER guard

EXPOSE 8080

CMD ["pnpm", "--dir", "examples/hono", "exec", "tsx", "server.ts"]
