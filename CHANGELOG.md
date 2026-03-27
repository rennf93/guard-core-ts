# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-03-27

### Initiial release

- Initial release of the @guardcore TypeScript ecosystem
- **@guardcore/core**: Framework-agnostic security engine (TypeScript port of guard-core Python)
  - 6 protocol interfaces (GuardRequest, GuardResponse, GuardResponseFactory, GuardMiddlewareProtocol, GeoIPHandler, AgentHandlerProtocol, RedisHandlerProtocol)
  - 44-field SecurityConfig with Zod validation and cross-field validators
  - 17-check SecurityCheckPipeline (Chain of Responsibility pattern)
  - 75 suspicious pattern definitions with 17 context sets
  - Detection engine: PatternCompiler (re2-wasm + worker_threads fallback), ContentPreprocessor, SemanticAnalyzer, PerformanceMonitor
  - 9 handlers: RedisManager, IPBanManager, RateLimitManager, CloudHandler, SusPatternsManager, SecurityHeadersManager, BehaviorTracker, DynamicRuleManager, IPInfoManager
  - HandlerRegistry pattern (no global singletons, test-friendly)
  - 20-method SecurityDecorator with TypeScript mixin composition
  - Full utils module: IP extraction, penetration detection, logging, agent events
  - Edge runtime support via Uint8Array protocols and re2-wasm
- **@guardcore/express**: Express middleware adapter with raw body preservation
- **@guardcore/fastify**: Fastify plugin adapter with onRequest/onSend hooks
- **@guardcore/nestjs**: NestJS middleware + GuardModule.forRoot() with DI
- **@guardcore/hono**: Hono middleware factory (edge-safe, lazy initialization)
- 681 tests with 100% statement/line coverage across 31 test files
- Comprehensive CLAUDE.md with TypeScript development standards
