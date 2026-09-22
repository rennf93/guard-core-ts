export { PatternCompiler } from './compiler.js';
export type { MatchResult } from './compiler.js';
export { ContentPreprocessor } from './preprocessor.js';
export { PerformanceMonitor } from './monitor.js';
export type { PatternReport, PatternStats, PerformanceMetric } from './monitor.js';
export { SemanticAnalyzer } from './semantic.js';
export type { SemanticAnalysis } from './semantic.js';
export { looksLikeBinaryContent, buildBinaryPrefix } from './binary.js';
export { bounded_finditer } from './scan-window.js';
export {
  compilePythonPattern,
  matchAt,
  matchSpan,
  searchAt,
  searchSpan,
  finditerSpan,
  findall,
  pySearch,
  fullmatch,
} from './regex-compat.js';
