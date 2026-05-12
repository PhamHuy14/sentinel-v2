/**
 * HuggingFace Inference API Provider Adapter (Adapter cho nhà cung cấp HuggingFace)
 *
 * Gói miễn phí: https://huggingface.co/inference-api
 * Mô hình: meta-llama/Llama-3.1-8B-Instruct (Messages API, miễn phí)
 * Bien moi truong: HF_API_KEY (doc trong Electron main process)
 *
 * FIX v2.1:
 *  - Chuyển từ Legacy Text-Generation API → Messages API (OpenAI-compatible)
 *    Endpoint mới: /models/{model}/v1/chat/completions
 *  - Đổi model: Mistral-7B-Instruct-v0.3 (đã bị xóa khỏi serverless)
 *    → meta-llama/Llama-3.1-8B-Instruct (vẫn hoạt động trên HF free tier)
 *  - Hỗ trợ đọc VITE_HF_MODELS (comma-separated) để fallback
 */

import { ProviderMetricsTracker } from '../metricsTracker.js';
import {
    GenerateOptions,
    LLMProvider,
    ProviderError,
    ProviderHealth,
} from '../types';

const HF_BASE_URL = 'https://api-inference.huggingface.co/models';
const DEFAULT_TIMEOUT = 30_000; // HF cold-starts có thể chậm

// FIX: Danh sách model hoạt động trên HF serverless (2025)
const FALLBACK_MODELS = [
  'meta-llama/Llama-3.1-8B-Instruct',       // Nhanh, tốt, miễn phí
  'Qwen/Qwen2.5-7B-Instruct',               // Fallback #1 - chất lượng cao
  'microsoft/Phi-3-mini-4k-instruct',        // Fallback #2 - nhỏ, nhanh
  'HuggingFaceH4/zephyr-7b-beta',           // Fallback #3 - ổn định
];

type AiFetch = (payload: {
  providerId: 'huggingface';
  url: string;
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  timeoutMs?: number;
}) => Promise<{ ok: boolean; status: number; body: string; headers?: Record<string, string> }>;

function getAiFetch(): AiFetch | null {
  const bridge = (globalThis as { owaspWorkbench?: { aiFetch?: AiFetch } }).owaspWorkbench;
  return bridge?.aiFetch ?? null;
}

function extractContentType(headers?: Record<string, string>): string {
  return (headers?.['content-type'] || headers?.['Content-Type'] || '').toLowerCase();
}

function shouldParseJson(body: string, contentType: string): boolean {
  const trimmed = body.trim();
  if (!trimmed) return false;
  if (contentType.includes('application/json')) return true;
  return trimmed.startsWith('{') || trimmed.startsWith('[');
}

async function fetchJson(url: string, payload: { headers: Record<string, string>; body: string }, timeoutMs: number) {
  const aiFetch = getAiFetch();
  if (aiFetch) {
    const resp = await aiFetch({ providerId: 'huggingface', url, method: 'POST', headers: payload.headers, body: payload.body, timeoutMs });
    return { ok: resp.ok, status: resp.status, body: resp.body || '', contentType: extractContentType(resp.headers) };
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: payload.headers,
      body: payload.body,
      signal: controller.signal,
    });
    const text = await res.text();
    return { ok: res.ok, status: res.status, body: text, contentType: extractContentType({ 'content-type': res.headers.get('content-type') || '' }) };
  } finally {
    clearTimeout(timer);
  }
}

/** Đọc danh sách model từ VITE_HF_MODELS hoặc dùng fallback mặc định */
function resolveModelList(): string[] {
  const fromEnv = import.meta.env.VITE_HF_MODELS ?? import.meta.env.VITE_HF_MODEL ?? '';
  if (fromEnv.trim()) {
    return fromEnv.split(',').map((m: string) => m.trim()).filter(Boolean);
  }
  return FALLBACK_MODELS;
}

export class HuggingFaceProvider implements LLMProvider {
  readonly id = 'huggingface';
  readonly label = 'HuggingFace (Llama-3.1 8B)';
  readonly supportsJsonMode = false;

  private readonly metrics: ProviderMetricsTracker;
  private readonly modelList: string[];

  constructor(metrics: ProviderMetricsTracker) {
    this.metrics = metrics;
    this.modelList = resolveModelList();
  }

  async generate(prompt: string, options: GenerateOptions = {}): Promise<string> {
    const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT;
    const start = Date.now();
    const systemPrompt = options.systemPrompt ?? 'You are a helpful security assistant.';

    let lastError: ProviderError | null = null;

    for (const model of this.modelList) {
      // FIX: Dùng Messages API (OpenAI-compatible) thay vì Legacy text-generation API
      // Endpoint: /models/{model}/v1/chat/completions
      const url = `${HF_BASE_URL}/${model}/v1/chat/completions`;

      const body = {
        model,
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: prompt },
        ],
        max_tokens: options.maxTokens ?? 1024,
        temperature: 0.7,
        stream: false,
      };

      try {
        const headers = {
          'Content-Type': 'application/json',
        };

        const res = await fetchJson(url, { headers, body: JSON.stringify(body) }, timeoutMs);
        const latency = Date.now() - start;

        // FIX: 404 = model không hỗ trợ Messages API → thử model tiếp theo
        if (res.status === 404 || res.status === 400) {
          lastError = new ProviderError('bad_request', this.id, `Model "${model}" not available via Messages API (HTTP ${res.status})`, res.status);
          continue;
        }

        if (res.status === 429 || res.status === 503) {
          this.metrics.recordFailure(this.id, latency);
          throw new ProviderError('rate_limit', this.id, `HF throttle HTTP ${res.status}`, res.status);
        }
        if (res.status === 401 || res.status === 403) {
          this.metrics.recordFailure(this.id, latency);
          throw new ProviderError('auth_error', this.id, 'HF_API_KEY not set or rejected', res.status);
        }

        if (!res.ok) {
          this.metrics.recordFailure(this.id, latency);
          const kind = res.status >= 500 ? 'server_error' : 'bad_request';
          throw new ProviderError(kind, this.id, `HTTP ${res.status}`, res.status);
        }

        if (!shouldParseJson(res.body, res.contentType)) {
          this.metrics.recordFailure(this.id, latency);
          throw new ProviderError('bad_request', this.id, 'Non-JSON response', res.status);
        }

        let data: { choices?: { message?: { content?: string } }[] } | null = null;
        try {
          data = res.body ? JSON.parse(res.body) : null;
        } catch {
          this.metrics.recordFailure(this.id, latency);
          throw new ProviderError('bad_request', this.id, 'Invalid JSON response', res.status);
        }

        const text = data?.choices?.[0]?.message?.content ?? '';
        this.metrics.recordSuccess(this.id, latency);
        return text.trim();

      } catch (err) {
        if ((err as Error).name === 'AbortError') {
          this.metrics.recordFailure(this.id, timeoutMs);
          throw new ProviderError('timeout', this.id, 'Request timed out');
        }
        if (err instanceof ProviderError) {
          if (err.kind === 'rate_limit' || err.kind === 'auth_error') throw err;
          lastError = err;
          continue;
        }
        this.metrics.recordFailure(this.id, Date.now() - start);
        throw new ProviderError('unknown', this.id, String(err));
      }
    }

    this.metrics.recordFailure(this.id, Date.now() - start);
    throw lastError ?? new ProviderError('bad_request', this.id, 'All HuggingFace models unavailable');
  }

  async health(): Promise<ProviderHealth> {
    return this.metrics.getHealth(this.id, false);
  }

  async estimateCostOrQuota(): Promise<number> {
    // HF serverless free tier: ~1.000 request/ngày
    return 1_000;
  }
}



