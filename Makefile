.PHONY: install build clean test test-all test-coverage lint typecheck \
       build-core build-express build-fastify build-nestjs build-hono \
       bump-version prune stop restart serve-docs build-docs

install:
	pnpm install

build:
	pnpm build

clean:
	pnpm clean

test:
	pnpm --filter @guardcore/core test

test-all:
	pnpm test

test-coverage:
	cd packages/core && npx vitest run --coverage

lint:
	pnpm lint

typecheck: lint

build-core:
	pnpm --filter @guardcore/core build

build-express:
	pnpm --filter @guardcore/express build

build-fastify:
	pnpm --filter @guardcore/fastify build

build-nestjs:
	pnpm --filter @guardcore/nestjs build

build-hono:
	pnpm --filter @guardcore/hono build

bump-version:
	@if [ -z "$(VERSION)" ]; then echo "Usage: make bump-version VERSION=x.y.z"; exit 1; fi
	node .github/scripts/bump-version.mjs $(VERSION)

prune:
	find . -name "node_modules" -type d -prune -exec rm -rf {} + 2>/dev/null || true
	find . -name "dist" -type d -prune -exec rm -rf {} + 2>/dev/null || true
	find . -name ".turbo" -type d -prune -exec rm -rf {} + 2>/dev/null || true

serve-docs:
	cd docs && npx astro dev

build-docs:
	cd docs && npx astro build

stop:
	docker compose down 2>/dev/null || true

restart: stop
	docker compose up -d
