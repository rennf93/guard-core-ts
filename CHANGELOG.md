# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Detection: the live middleware now runs the FULL canonical pattern table through `SusPatternsManager.detect` for every request surface (query param names and values, URL path, header names and values, JSON body keys and leaves, form fields, raw blob), exactly mirroring the reference detect flow (`guard_core/_utils/penetration_detection.py` + `detection_scan.py`). Previously the `SuspiciousActivityCheck` only ran a hardcoded 7-pattern shortcut, so the TypeScript middleware detected far less than every other family: recon probes, tautologies, event-handler XSS, NoSQL operator keys and all case/encoding variants that live only in the 157-row table were missed. JSON leaves embedded inside non-body values carry the `:embedded_json` context suffix so the engine's per-context gates (recon bare-word rule, source-extension probe rule) apply to them; body JSON values scan as `request_body` per the reference context matrix. The retired 7-pattern shortcut path is gone; the public `detectPenetrationAttempt` export now delegates to the same engine on a shared default manager
- Adapters: block and error responses are `text/plain; charset=utf-8` carrying the message itself, instead of `application/json` wrapping it in a `{detail: ...}` envelope, mirroring the Python family convention (fastapi-guard #144). Applies across the express, fastify, hono and nestjs response factories (redirect responses keep no body, custom_error_responses messages stay plain text), and a `customResponseModifier` that sets its own content type still wins
- Detection: recon whole-value rows with an optional leading path separator no longer flag bare words such as "default" or "README.md" scanned in query/body contexts; bare words remain probes as the url_path (or in unknown contexts) and separator-prefixed paths are still threats. Parity with guard-core #115/#116 (commit 08f79d67)
- Logging: `sanitizeForLog` now emits pure ASCII like the reference `_sanitize_for_log` (guard-core commit f5d53ca5, log half). Control characters and every non-ASCII code point become `\uXXXX` escapes (lone surrogate-escaped bytes in the 0xDC80-0xDCFF range become `\xNN`), so log lines can never raise on legacy code pages such as Windows cp1252

## [4.0.4] - 2026-09-24

### Parity with guard-core 4.0.4

- Version train aligned with the engine family across all five packages (@guardcore/core, express, fastify, nestjs, hono)
- Binary-noise gates, including the SQLi comment-terminator binary gate
- Corpus harmonization with the guard-core 4.0.3/4.0.4 conformance set

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
