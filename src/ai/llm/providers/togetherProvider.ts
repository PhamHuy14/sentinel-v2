/**
 * Together.ai Provider Adapter
 *
 * Free tier: https://api.together.xyz
 * Model: mistralai/Mixtral-8x7B-Instruct-v0.1
 * Env var: VITE_TOGETHER_API_KEY
 */

import {
  GenerateOptions,
  LLMProvider,
  ProviderError,
  ProviderHealth,
} from '../types.js';
import { ProviderMetricsTracker } from '../metricsTracker.js';

const TOGETHER_API_URL = 'https://api.together.xyz/v1/chat/completions';
const DEFAULT_MODEL    = 'mistralai/Mixtral-8x7B-Instruct-v0.1';
const DEFAULT_TIMEOUT  = 15_000;

export class TogetherProvider implements LLMProvider {
  readonly id = 'together';
  readonly label = 'Together.ai (Mixtral-8x7B)';
  readonly supportsJsonMode = false;

  private readonly apiKey: string;
  private readonly metrics: ProviderMetricsTracker;

  constructor(metrics: ProviderMetricsTracker) {
    this.apiKey = (import.meta as unknown as Record<string, Record<string, string>>).env?.VITE_TOGETHER_API_KEY ?? '';
    this.metrics = metrics;
  }

  async generate(prompt: string, options: GenerateOptions = {}): Promise<string> {
    if (!this.apiKey) throw new ProviderError('auth_error', this.id, 'VITE_TOGETHER_API_KEY not set');

    const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    const body = {
      model: DEFAULT_MODEL,
      messages: [
        { role: 'system', content: options.systemPrompt ?? 'You are a helpful security assistant.' },
        { role: 'user',   content: prompt },
      ],
      max_tokens: options.maxTokens ?? 512,
      temperature: 0.7,
    };

    const start = Date.now();
    try {
      const res = await fetch(TOGETHER_API_URL, {
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

      if (res.status === 429) {
        this.metrics.recordFailure(this.id, latency);
        throw new ProviderError('rate_limit', this.id, 'Rate limit exceeded', 429);
      }
      if (!res.ok) {
        this.metrics.recordFailure(this.id, latency);
        const kind = res.status >= 500 ? 'server_error' : 'bad_request';
        throw new ProviderError(kind, this.id, `HTTP ${res.status}`, res.status);
      }

      const data = await res.json() as { choices?: { message?: { content?: string } }[] };
      const text = data.choices?.[0]?.message?.content ?? '';
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
    // Together free tier: $1 credit → generous for small queries
    return this.apiKey ? 10_000 : 0;
  }
}
