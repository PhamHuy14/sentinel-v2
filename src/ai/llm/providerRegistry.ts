/**
 * Provider Registry (Noi dang ky Nha cung cap)
 *
 * Tao va ket noi tat ca cac nha cung cap cung voi LLM router.
 * Goi ham `buildLLMRouter()` mot lan khi khoi dong ung dung va truyen no vao `initOrchestrator()`.
 *
 * NANG CAP v2:
 *  - Thu tu uu tien mac dinh: Groq -> Gemini -> OpenRouter -> Together -> HuggingFace
 *    (Groq mien phi, nhanh nhat; Gemini co flash mien phi)
 *  - readEnvConfig doc them VITE_LLM_MAX_OUTPUT_TOKENS de sync voi sentinelAI
 *
 * De them mot nha cung cap moi:
 *   1. Tao mot class implement LLMProvider trong thu muc providers/
 *   2. Import class do vao day va them vao mang `providers`
 *   3. Them id cua no vao VITE_LLM_PROVIDER_PRIORITY trong file .env
 */

import { LLMRouter } from './llmRouter.js';
import { ProviderMetricsTracker } from './metricsTracker.js';
import { GeminiProvider } from './providers/geminiProvider.js';
import { GroqProvider } from './providers/groqProvider.js';
import { HuggingFaceProvider } from './providers/huggingfaceProvider.js';
import { OpenRouterProvider } from './providers/openrouterProvider.js';
import { TogetherProvider } from './providers/togetherProvider.js';
import { DEFAULT_ROUTER_CONFIG, RouterConfig } from './types';

/** Doc cac cau hinh ghi de (tuy chon) tu bien moi truong Vite */
function readEnvConfig(): Partial<RouterConfig> {
  const cfg: Partial<RouterConfig> = {};

  if (import.meta.env.VITE_LLM_PROVIDER_PRIORITY) {
    cfg.providerPriority = import.meta.env.VITE_LLM_PROVIDER_PRIORITY.split(',').map((s: string) => s.trim());
  }
  if (import.meta.env.VITE_LLM_TIMEOUT_MS) {
    cfg.timeoutMs = Number(import.meta.env.VITE_LLM_TIMEOUT_MS);
  }
  if (import.meta.env.VITE_LLM_MAX_RETRIES) {
    cfg.maxRetries = Number(import.meta.env.VITE_LLM_MAX_RETRIES);
  }
  if (import.meta.env.VITE_LLM_CACHE_TTL_MS) {
    cfg.cacheTtlMs = Number(import.meta.env.VITE_LLM_CACHE_TTL_MS);
  }
  if (import.meta.env.VITE_LLM_CROSS_CHECK_ENABLED !== undefined) {
    cfg.crossCheckEnabled = import.meta.env.VITE_LLM_CROSS_CHECK_ENABLED !== 'false';
  }
  if (import.meta.env.VITE_LLM_CROSS_CHECK_THRESHOLD) {
    cfg.crossCheckThreshold = Number(import.meta.env.VITE_LLM_CROSS_CHECK_THRESHOLD);
  }
  if (import.meta.env.VITE_LLM_MAX_INPUT_TOKENS) {
    cfg.maxInputTokens = Number(import.meta.env.VITE_LLM_MAX_INPUT_TOKENS);
  }
  if (import.meta.env.VITE_LLM_MAX_OUTPUT_TOKENS) {
    cfg.maxOutputTokens = Number(import.meta.env.VITE_LLM_MAX_OUTPUT_TOKENS);
  }

  return cfg;
}

/**
 * Xay dung va tra ve mot LLMRouter da duoc ket noi day du.
 * Thu tu provider: Groq -> Gemini -> OpenRouter -> Together -> HuggingFace
 * Cac nha cung cap khong co API key se co diem suc khoe (health score) = 0 va tu dong bi bo qua.
 */
export function buildLLMRouter(): LLMRouter {
  const config  = { ...DEFAULT_ROUTER_CONFIG, ...readEnvConfig() };
  const metrics = new ProviderMetricsTracker(
    config.circuitBreakerThreshold,
    config.circuitResetMs,
  );

  // NANG CAP: Groq dat dau tien (nhanh, mien phi, quota tot)
  const providers = [
    new GroqProvider(metrics),
    new GeminiProvider(metrics),
    new OpenRouterProvider(metrics),
    new TogetherProvider(metrics),
    new HuggingFaceProvider(metrics),
  ];

  return new LLMRouter(providers, metrics, config);
}

