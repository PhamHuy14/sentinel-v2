/**
 * LLM Provider Interface & Shared Types
 *
 * Defines the contract every provider adapter must implement,
 * plus the canonical response object returned to callers.
 */

// ── Provider health snapshot ───────────────────────────────────────────────────
export interface ProviderHealth {
  /** 0–1 score; 1 = fully healthy */
  score: number;
  /** Estimated remaining quota (arbitrary units, provider-specific) */
  remainingQuota: number;
  /** Average latency in ms from recent calls */
  avgLatencyMs: number;
  /** Error rate in last N calls (0–1) */
  recentErrorRate: number;
  /** Whether the circuit-breaker is open */
  circuitOpen: boolean;
}

// ── Provider abstraction ───────────────────────────────────────────────────────
export interface LLMProvider {
  /** Unique identifier, e.g. "groq", "together", "huggingface" */
  readonly id: string;
  /** Human-readable label */
  readonly label: string;
  /** Whether this provider supports native JSON-mode output */
  readonly supportsJsonMode: boolean;

  /**
   * Generate a completion for `prompt`.
   * @param prompt - The sanitized prompt string.
   * @param options - Optional overrides (maxTokens, systemPrompt, jsonMode).
   * @returns The raw text response.
   * @throws {ProviderError} on API-level errors.
   */
  generate(prompt: string, options?: GenerateOptions): Promise<string>;

  /**
   * Quick liveness / quota check.
   * Should be lightweight — ideally a cheap metadata call or cached.
   */
  health(): Promise<ProviderHealth>;

  /**
   * Returns an estimate of remaining quota.
   * May return Infinity when quota is unknown or unlimited.
   */
  estimateCostOrQuota(): Promise<number>;
}

// ── Generate options ───────────────────────────────────────────────────────────
export interface GenerateOptions {
  maxTokens?: number;
  systemPrompt?: string;
  jsonMode?: boolean;
  /** Request-level timeout override in ms */
  timeoutMs?: number;
}

// ── Provider errors ───────────────────────────────────────────────────────────
export type ProviderErrorKind =
  | 'rate_limit'      // 429
  | 'server_error'    // 5xx
  | 'timeout'
  | 'auth_error'      // 401/403
  | 'bad_request'     // 400
  | 'unknown';

export class ProviderError extends Error {
  constructor(
    public readonly kind: ProviderErrorKind,
    public readonly providerId: string,
    message: string,
    public readonly statusCode?: number,
  ) {
    super(message);
    this.name = 'ProviderError';
  }
}

// ── Canonical AI response ─────────────────────────────────────────────────────
export interface AiResponse {
  /** The final answer to return to the user */
  answer: string;
  /** Confidence score 0–1 */
  confidence: number;
  /** All providers that were attempted */
  providersTried: string[];
  /** The provider whose answer was ultimately used */
  providerUsed: string;
  /** Whether cross-checking was performed */
  crossChecked: boolean;
  /** Non-fatal warnings (e.g. "provider X timed out, used fallback") */
  warnings: string[];
  /** Total wall-clock latency in ms */
  latencyMs: number;
  /** Source layer: 'knowledge_base' | 'llm' | 'synthesized' */
  source: 'knowledge_base' | 'llm' | 'synthesized';
}

// ── Router config ─────────────────────────────────────────────────────────────
export interface RouterConfig {
  /**
   * IDs of providers in priority order.
   * The router will try higher-priority providers first,
   * subject to health scoring.
   */
  providerPriority: string[];

  /** Weights used in provider selection score (0–1 range each) */
  selectionWeights: {
    health: number;
    quota: number;
    latency: number;
    errorRate: number;
  };

  /** Max time for a single provider call, ms */
  timeoutMs: number;

  /** How many times to retry a failing call before next provider */
  maxRetries: number;

  /** Base delay for exponential back-off, ms */
  retryBaseDelayMs: number;

  /** Maximum back-off delay cap, ms */
  retryMaxDelayMs: number;

  /**
   * Number of consecutive failures that trip the circuit breaker.
   * Once open, the provider is skipped for `circuitResetMs`.
   */
  circuitBreakerThreshold: number;

  /** How long an open circuit stays open before being retried, ms */
  circuitResetMs: number;

  /** TTL for cached answers, ms */
  cacheTtlMs: number;

  /** Maximum cache entries */
  cacheMaxSize: number;

  /**
   * Minimum confidence score from a single provider to skip cross-check.
   * Below this threshold a second provider is also queried.
   */
  crossCheckThreshold: number;

  /**
   * Whether cross-checking is enabled at all.
   * Can be toggled per-environment via env var.
   */
  crossCheckEnabled: boolean;

  /** Max tokens sent to provider (input guard) */
  maxInputTokens: number;

  /** Max tokens requested from provider (output guard) */
  maxOutputTokens: number;
}

// ── Default config ─────────────────────────────────────────────────────────────
export const DEFAULT_ROUTER_CONFIG: RouterConfig = {
  providerPriority: ['groq', 'together', 'huggingface'],
  selectionWeights: { health: 0.4, quota: 0.25, latency: 0.2, errorRate: 0.15 },
  timeoutMs: 12_000,
  maxRetries: 2,
  retryBaseDelayMs: 300,
  retryMaxDelayMs: 4_000,
  circuitBreakerThreshold: 5,
  circuitResetMs: 60_000,
  cacheTtlMs: 5 * 60_000,   // 5 min
  cacheMaxSize: 200,
  crossCheckThreshold: 0.65,
  crossCheckEnabled: true,
  maxInputTokens: 1_500,
  maxOutputTokens: 512,
};
