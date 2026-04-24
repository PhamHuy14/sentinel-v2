/**
 * LLM Router — Multi-Provider Orchestrator
 *
 * Layer 2 of the hybrid AI system.
 * Responsibilities:
 *  - Select the healthiest available provider
 *  - Retry with backoff on transient errors
 *  - Cross-check answers from two providers when confidence is low
 *  - Cache responses with configurable TTL
 *  - Return the canonical AiResponse object
 */

import {
  AiResponse,
  DEFAULT_ROUTER_CONFIG,
  LLMProvider,
  ProviderError,
  RouterConfig,
} from './types.js';
import { AnswerCache } from './answerCache.js';
import { crossCheck } from './crossChecker.js';
import { ProviderMetricsTracker } from './metricsTracker.js';
import { sanitizePrompt } from './sanitizer.js';
import { withRetry } from './retry.js';

// ── System prompt used for all LLM calls ─────────────────────────────────────
const SECURITY_SYSTEM_PROMPT = `You are SENTINEL AI, an expert cybersecurity assistant specializing in OWASP Top 10 vulnerabilities, web application security, and penetration testing.

Rules:
- Answer ONLY security-related questions
- Be concise, accurate, and reference OWASP when relevant
- Never provide working exploit code or step-by-step attack instructions
- Format answers in clear Markdown
- If unsure, say so rather than guessing`;

// ── Provider selection scoring ────────────────────────────────────────────────
interface ScoredProvider {
  provider: LLMProvider;
  score: number;
}

export class LLMRouter {
  private readonly providers: Map<string, LLMProvider>;
  private readonly metrics: ProviderMetricsTracker;
  private readonly cache: AnswerCache;
  private readonly config: RouterConfig;

  constructor(
    providers: LLMProvider[],
    metrics: ProviderMetricsTracker,
    config: Partial<RouterConfig> = {},
  ) {
    this.config    = { ...DEFAULT_ROUTER_CONFIG, ...config };
    this.metrics   = metrics;
    this.cache     = new AnswerCache(this.config.cacheTtlMs, this.config.cacheMaxSize);
    this.providers = new Map(providers.map(p => [p.id, p]));
  }

  // ── Provider selection ──────────────────────────────────────────────────────

  /**
   * Score each provider and return them sorted best-first.
   * Skips providers whose circuit-breaker is open.
   */
  private async rankProviders(): Promise<ScoredProvider[]> {
    const w = this.config.selectionWeights;
    const ranked: ScoredProvider[] = [];

    // Respect priority order as tie-breaker
    const prioritised = this.config.providerPriority
      .map(id => this.providers.get(id))
      .filter((p): p is LLMProvider => p !== undefined);

    // Add any providers not in priority list at the end
    for (const p of this.providers.values()) {
      if (!prioritised.includes(p)) prioritised.push(p);
    }

    for (const provider of prioritised) {
      if (this.metrics.isCircuitOpen(provider.id)) continue;

      const health = await provider.health();
      if (health.circuitOpen) continue;

      const quota = await provider.estimateCostOrQuota();
      const normalizedQuota = quota === 0 ? 0 : Math.min(1, quota / 15_000);

      const latencyScore  = Math.max(0, 1 - health.avgLatencyMs / 15_000);
      const errorPenalty  = health.recentErrorRate;

      const score =
        w.health    * health.score      +
        w.quota     * normalizedQuota   +
        w.latency   * latencyScore      +
        w.errorRate * (1 - errorPenalty);

      ranked.push({ provider, score });
    }

    return ranked.sort((a, b) => b.score - a.score);
  }

  // ── Single provider call with retry ────────────────────────────────────────
  private async callProvider(provider: LLMProvider, prompt: string): Promise<string> {
    return withRetry(
      () => provider.generate(prompt, {
        systemPrompt:  SECURITY_SYSTEM_PROMPT,
        maxTokens:     this.config.maxOutputTokens,
        timeoutMs:     this.config.timeoutMs,
      }),
      {
        maxRetries:   this.config.maxRetries,
        baseDelayMs:  this.config.retryBaseDelayMs,
        maxDelayMs:   this.config.retryMaxDelayMs,
        shouldRetry:  (err) => {
          const kind = (err as ProviderError).kind;
          // Only retry transient errors
          return kind === 'server_error' || kind === 'timeout' || kind === 'rate_limit';
        },
      },
    );
  }

  // ── Confidence estimation from a single answer ─────────────────────────────
  private estimateConfidence(answer: string): number {
    if (!answer || answer.trim().length < 30)  return 0.20;
    if (answer.length > 800)                   return 0.75; // detailed
    if (answer.length > 300)                   return 0.65;
    return 0.50;
  }

  // ── Main query method ───────────────────────────────────────────────────────

  /**
   * Query the LLM tier.
   * @param question - The user question (already validated as security-related).
   * @returns Canonical AiResponse.
   */
  async query(question: string): Promise<AiResponse> {
    const start = Date.now();

    // ── 0. Cache hit ──────────────────────────────────────────────────────────
    const cached = this.cache.get(question);
    if (cached) {
      return {
        answer:         cached.answer,
        confidence:     cached.confidence,
        providersTried: [cached.providerUsed],
        providerUsed:   cached.providerUsed,
        crossChecked:   cached.crossChecked,
        warnings:       ['Served from cache'],
        latencyMs:      Date.now() - start,
        source:         'llm',
      };
    }

    // ── 1. Sanitize prompt ────────────────────────────────────────────────────
    const { prompt, warnings } = sanitizePrompt(question, this.config.maxInputTokens);
    const providersTried: string[] = [];

    // ── 2. Rank providers ─────────────────────────────────────────────────────
    const ranked = await this.rankProviders();
    if (ranked.length === 0) {
      return this.buildErrorResponse('No LLM providers available', providersTried, start, warnings);
    }

    // ── 3. Primary call ───────────────────────────────────────────────────────
    let primaryAnswer   = '';
    let primaryProvider = '';
    let primaryError: unknown = null;

    for (const { provider } of ranked) {
      try {
        primaryAnswer   = await this.callProvider(provider, prompt);
        primaryProvider = provider.id;
        providersTried.push(provider.id);
        break;
      } catch (err) {
        primaryError = err;
        providersTried.push(provider.id);
        warnings.push(`${provider.id} failed: ${(err as Error).message}`);
      }
    }

    if (!primaryAnswer) {
      return this.buildErrorResponse(
        `All providers failed: ${(primaryError as Error)?.message ?? 'unknown error'}`,
        providersTried, start, warnings,
      );
    }

    const initialConfidence = this.estimateConfidence(primaryAnswer);

    // ── 4. Cross-check (optional) ─────────────────────────────────────────────
    const shouldCrossCheck =
      this.config.crossCheckEnabled &&
      initialConfidence < this.config.crossCheckThreshold &&
      ranked.length >= 2;

    if (!shouldCrossCheck) {
      // Cache and return single-provider result
      this.cache.set(question, {
        answer:       primaryAnswer,
        confidence:   initialConfidence,
        providerUsed: primaryProvider,
        crossChecked: false,
      });
      return {
        answer:         primaryAnswer,
        confidence:     initialConfidence,
        providersTried,
        providerUsed:   primaryProvider,
        crossChecked:   false,
        warnings,
        latencyMs:      Date.now() - start,
        source:         'llm',
      };
    }

    // Find a second provider different from primary
    const secondCandidate = ranked.find(r => r.provider.id !== primaryProvider);
    let finalAnswer    = primaryAnswer;
    let finalProvider  = primaryProvider;
    let finalConfidence = initialConfidence;
    let crossChecked   = false;

    if (secondCandidate) {
      try {
        const secondAnswer = await this.callProvider(secondCandidate.provider, prompt);
        providersTried.push(secondCandidate.provider.id);

        const result = crossCheck(primaryAnswer, secondAnswer);
        finalAnswer    = result.chosenAnswer;
        finalConfidence = result.confidence;
        finalProvider  = result.chosenFrom === 'secondary'
          ? secondCandidate.provider.id
          : result.chosenFrom === 'synthesized'
            ? 'synthesized'
            : primaryProvider;
        crossChecked   = true;
        warnings.push(`Cross-check: ${result.rationale}`);
      } catch (err) {
        warnings.push(`Secondary provider ${secondCandidate.provider.id} failed: ${(err as Error).message}`);
      }
    }

    this.cache.set(question, {
      answer:       finalAnswer,
      confidence:   finalConfidence,
      providerUsed: finalProvider,
      crossChecked,
    });

    return {
      answer:         finalAnswer,
      confidence:     finalConfidence,
      providersTried,
      providerUsed:   finalProvider,
      crossChecked,
      warnings,
      latencyMs:      Date.now() - start,
      source:         crossChecked ? 'synthesized' : 'llm',
    };
  }

  // ── Error response factory ─────────────────────────────────────────────────
  private buildErrorResponse(
    message: string,
    providersTried: string[],
    start: number,
    warnings: string[],
  ): AiResponse {
    return {
      answer:
        '⚠️ **AI service temporarily unavailable.**\n\n' +
        'All external AI providers are currently unreachable. ' +
        'The local knowledge base is still available — try rephrasing your question.\n\n' +
        `*Technical detail: ${message}*`,
      confidence:     0,
      providersTried,
      providerUsed:   'none',
      crossChecked:   false,
      warnings:       [...warnings, message],
      latencyMs:      Date.now() - start,
      source:         'llm',
    };
  }

  // ── Observability ──────────────────────────────────────────────────────────
  getMetricsSnapshot() {
    return this.metrics.snapshot();
  }

  getCacheSize(): number {
    return this.cache.size;
  }
}
