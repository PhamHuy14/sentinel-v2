/**
 * Together.ai Provider Adapter (Adapter cho nhà cung cấp Together.ai)
 *
 * Gói miễn phí: https://api.together.xyz
 * Mô hình: meta-llama/Llama-3.3-70B-Instruct-Turbo-Free (MIỄN PHÍ hoàn toàn)
 * Biến môi trường: TOGETHER_API_KEY (đọc trong Electron main process)
 *
 * FIX v2.1:
 *  - Đổi model mặc định: Qwen/Qwen2.5-72B-Instruct-Turbo (tốn credit)
 *    → meta-llama/Llama-3.3-70B-Instruct-Turbo-Free (hoàn toàn miễn phí)
 *  - Thêm danh sách model fallback free tier
 *  - Hỗ trợ đọc VITE_TOGETHER_MODELS từ env
 *  - Phân biệt lỗi 402 (hết credit) vs 404 (model không tồn tại)
 */

import { ProviderMetricsTracker } from '../metricsTracker.js';
import {
    GenerateOptions,
    LLMProvider,
    ProviderError,
    ProviderHealth,
} from '../types';

const TOGETHER_API_URL = 'https://api.together.xyz/v1/chat/completions';
const DEFAULT_TIMEOUT  = 20_000;

// FIX: Chỉ dùng model FREE tier (tên có "-Free" hoặc được liệt kê miễn phí)
const FALLBACK_MODELS = [
  'meta-llama/Llama-3.3-70B-Instruct-Turbo-Free', // Hoàn toàn miễn phí, ĐỀ XUẤT
  'meta-llama/Llama-3.2-11B-Vision-Instruct-Turbo', // Fallback #1 (free tier)
  'meta-llama/Llama-3.1-8B-Instruct-Turbo-Free',   // Fallback #2 (nhanh hơn)
];

type AiFetch = (payload: {
  providerId: 'together';
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
    const resp = await aiFetch({ providerId: 'together', url, method: 'POST', headers: payload.headers, body: payload.body, timeoutMs });
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

/** Đọc danh sách model từ VITE_TOGETHER_MODELS hoặc dùng fallback mặc định */
function resolveModelList(): string[] {
  const fromEnv = import.meta.env.VITE_TOGETHER_MODELS ?? import.meta.env.VITE_TOGETHER_MODEL ?? '';
  if (fromEnv.trim()) {
    return fromEnv.split(',').map((m: string) => m.trim()).filter(Boolean);
  }
  return FALLBACK_MODELS;
}

export class TogetherProvider implements LLMProvider {
  readonly id = 'together';
  readonly label = 'Together.ai (Llama-3.3 70B Free)';
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

    let lastError: ProviderError | null = null;

    for (const model of this.modelList) {
      const body = {
        model,
        messages: [
          { role: 'system', content: options.systemPrompt ?? 'You are a helpful security assistant.' },
          { role: 'user',   content: prompt },
        ],
        max_tokens: options.maxTokens ?? 1024,
        temperature: 0.7,
      };

      try {
        const headers = {
          'Content-Type': 'application/json',
        };
        const res = await fetchJson(TOGETHER_API_URL, { headers, body: JSON.stringify(body) }, timeoutMs);
        const latency = Date.now() - start;

        if (res.status === 429) {
          this.metrics.recordFailure(this.id, latency);
          throw new ProviderError('rate_limit', this.id, 'Rate limit exceeded', 429);
        }
        if (res.status === 401 || res.status === 403) {
          this.metrics.recordFailure(this.id, latency);
          throw new ProviderError('auth_error', this.id, 'TOGETHER_API_KEY not set or rejected', res.status);
        }

        // FIX: 402 = hết credit. Các model "-Free" sẽ không bao giờ trả về 402.
        // Nếu vẫn nhận 402 → thử model tiếp theo (model free tier khác)
        if (res.status === 402) {
          lastError = new ProviderError('bad_request', this.id, `Model "${model}" requires credits (HTTP 402) — try a Free-tier model`, 402);
          continue;
        }

        // 404 = model không tồn tại → thử tiếp
        if (res.status === 404 || res.status === 400) {
          lastError = new ProviderError('bad_request', this.id, `Model "${model}" not available (HTTP ${res.status})`, res.status);
          continue;
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
    throw lastError ?? new ProviderError('bad_request', this.id, 'All Together.ai models unavailable');
  }

  async health(): Promise<ProviderHealth> {
    return this.metrics.getHealth(this.id, false);
  }

  async estimateCostOrQuota(): Promise<number> {
    // Together free models: không giới hạn credit (chỉ rate-limited)
    return 10_000;
  }
}



