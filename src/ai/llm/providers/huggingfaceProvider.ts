/**
 * HuggingFace Inference API Provider Adapter
 *
 * Free tier: https://huggingface.co/inference-api
 * Model: mistralai/Mistral-7B-Instruct-v0.3
 * Env var: VITE_HF_API_KEY
 */

import {
  GenerateOptions,
  LLMProvider,
  ProviderError,
  ProviderHealth,
} from '../types.js';
import { ProviderMetricsTracker } from '../metricsTracker.js';

const HF_API_URL     = 'https://api-inference.huggingface.co/models/mistralai/Mistral-7B-Instruct-v0.3';
const DEFAULT_TIMEOUT = 20_000; // HF cold-starts can be slow

export class HuggingFaceProvider implements LLMProvider {
  readonly id = 'huggingface';
  readonly label = 'HuggingFace (Mistral-7B)';
  readonly supportsJsonMode = false;

  private readonly apiKey: string;
  private readonly metrics: ProviderMetricsTracker;

  constructor(metrics: ProviderMetricsTracker) {
    this.apiKey = (import.meta as unknown as Record<string, Record<string, string>>).env?.VITE_HF_API_KEY ?? '';
    this.metrics = metrics;
  }

  async generate(prompt: string, options: GenerateOptions = {}): Promise<string> {
    if (!this.apiKey) throw new ProviderError('auth_error', this.id, 'VITE_HF_API_KEY not set');

    const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    // HF text-generation endpoint uses a flat `inputs` + `parameters` body
    const systemPrompt = options.systemPrompt ?? 'You are a helpful security assistant.';
    const fullPrompt   = `[INST] ${systemPrompt}\n\n${prompt} [/INST]`;

    const body = {
      inputs: fullPrompt,
      parameters: {
        max_new_tokens: options.maxTokens ?? 512,
        return_full_text: false,
        temperature: 0.7,
      },
    };

    const start = Date.now();
    try {
      const res = await fetch(HF_API_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${this.apiKey}`,
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      });

      clearTimeout(timer);
      const latency = Date.now() - start;

      if (res.status === 429 || res.status === 503) {
        this.metrics.recordFailure(this.id, latency);
        throw new ProviderError('rate_limit', this.id, `HF throttle HTTP ${res.status}`, res.status);
      }
      if (!res.ok) {
        this.metrics.recordFailure(this.id, latency);
        const kind = res.status >= 500 ? 'server_error' : 'bad_request';
        throw new ProviderError(kind, this.id, `HTTP ${res.status}`, res.status);
      }

      // HF returns an array: [{generated_text: "..."}]
      const data = await res.json() as Array<{ generated_text?: string }> | { generated_text?: string };
      let text = '';
      if (Array.isArray(data)) {
        text = data[0]?.generated_text ?? '';
      } else {
        text = data.generated_text ?? '';
      }

      this.metrics.recordSuccess(this.id, latency);
      return text.trim();
    } catch (err) {
      clearTimeout(timer);
      if ((err as Error).name === 'AbortError') {
        this.metrics.recordFailure(this.id, timeoutMs);
        throw new ProviderError('timeout', this.id, 'Request timed out');
      }
      if (err instanceof ProviderError) throw err;
      this.metrics.recordFailure(this.id, Date.now() - start);
      throw new ProviderError('unknown', this.id, String(err));
    }
  }

  async health(): Promise<ProviderHealth> {
    return this.metrics.getHealth(this.id, !this.apiKey);
  }

  async estimateCostOrQuota(): Promise<number> {
    // HF free tier: roughly 1,000 calls/day on cold model
    return this.apiKey ? 1_000 : 0;
  }
}
