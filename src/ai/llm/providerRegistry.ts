/**
 * Provider Registry
 *
 * Creates and wires all providers + the LLM router.
 * Call `buildLLMRouter()` once at app startup and pass it to `initOrchestrator()`.
 *
 * To add a new provider:
 *   1. Create a class implementing LLMProvider in providers/
 *   2. Import it here and add to the `providers` array
 *   3. Add its id to VITE_LLM_PROVIDER_PRIORITY in .env
 */

import { LLMRouter } from './llmRouter.js';
import { ProviderMetricsTracker } from './metricsTracker.js';
import { DEFAULT_ROUTER_CONFIG, RouterConfig } from './types.js';
import { GroqProvider } from './providers/groqProvider.js';
import { TogetherProvider } from './providers/togetherProvider.js';
import { HuggingFaceProvider } from './providers/huggingfaceProvider.js';

/** Read optional env overrides from Vite */
function readEnvConfig(): Partial<RouterConfig> {
  const env = (import.meta as unknown as Record<string, Record<string, string>>).env ?? {};

  const cfg: Partial<RouterConfig> = {};

  if (env.VITE_LLM_PROVIDER_PRIORITY) {
    cfg.providerPriority = env.VITE_LLM_PROVIDER_PRIORITY.split(',').map(s => s.trim());
  }
  if (env.VITE_LLM_TIMEOUT_MS) {
    cfg.timeoutMs = Number(env.VITE_LLM_TIMEOUT_MS);
  }
  if (env.VITE_LLM_MAX_RETRIES) {
    cfg.maxRetries = Number(env.VITE_LLM_MAX_RETRIES);
  }
  if (env.VITE_LLM_CACHE_TTL_MS) {
    cfg.cacheTtlMs = Number(env.VITE_LLM_CACHE_TTL_MS);
  }
  if (env.VITE_LLM_CROSS_CHECK_ENABLED !== undefined) {
    cfg.crossCheckEnabled = env.VITE_LLM_CROSS_CHECK_ENABLED !== 'false';
  }
  if (env.VITE_LLM_CROSS_CHECK_THRESHOLD) {
    cfg.crossCheckThreshold = Number(env.VITE_LLM_CROSS_CHECK_THRESHOLD);
  }
  if (env.VITE_LLM_MAX_INPUT_TOKENS) {
    cfg.maxInputTokens = Number(env.VITE_LLM_MAX_INPUT_TOKENS);
  }
  if (env.VITE_LLM_MAX_OUTPUT_TOKENS) {
    cfg.maxOutputTokens = Number(env.VITE_LLM_MAX_OUTPUT_TOKENS);
  }

  return cfg;
}

/**
 * Build and return a fully wired LLMRouter.
 * Providers with no API key will have health score=0 and be skipped automatically.
 */
export function buildLLMRouter(): LLMRouter {
  const config  = { ...DEFAULT_ROUTER_CONFIG, ...readEnvConfig() };
  const metrics = new ProviderMetricsTracker(
    config.circuitBreakerThreshold,
    config.circuitResetMs,
  );

  const providers = [
    new GroqProvider(metrics),
    new TogetherProvider(metrics),
    new HuggingFaceProvider(metrics),
  ];

  return new LLMRouter(providers, metrics, config);
}
