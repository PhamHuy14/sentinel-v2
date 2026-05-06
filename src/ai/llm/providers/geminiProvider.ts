/**
 * Google Gemini Provider Adapter (Adapter cho nhà cung cấp Google Gemini)
 *
 * Gói miễn phí: https://aistudio.google.com
 * Mô hình: gemini-2.0-flash (model mới nhất, nhanh, miễn phí)
 * Biến môi trường: VITE_GEMINI_API_KEY
 *
 * FIX v2.1:
 *  - Đổi model mặc định: gemini-1.5-flash → gemini-2.0-flash (mới hơn, tốt hơn)
 *  - Sửa tên env var: VITE_GEMINI_MODEL → VITE_GEMINI_MODELS (khớp với .env)
 *  - Hỗ trợ danh sách model fallback (comma-separated)
 *  - Thử model tiếp theo khi nhận 404 (model deprecated/không tồn tại)
 */

import { ProviderMetricsTracker } from '../metricsTracker.js';
import {
    GenerateOptions,
    LLMProvider,
    ProviderError,
    ProviderHealth,
} from '../types';

const DEFAULT_TIMEOUT = 20_000;

// FIX: Danh sách model fallback Gemini (2025)
const FALLBACK_MODELS = [
  'gemini-2.0-flash',          // Tốt nhất, miễn phí, ĐỀ XUẤT
  'gemini-2.0-flash-lite',     // Nhỏ hơn, nhanh hơn, fallback #1
  'gemini-1.5-flash',          // Model cũ hơn, fallback #2
  'gemini-1.5-flash-latest',   // Alias fallback #3
];

type AiFetch = (payload: {
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

async function fetchJson(url: string, payload: { headers: Record<string, string>; body: string }, timeoutMs: number, signal?: AbortSignal) {
  const aiFetch = getAiFetch();
  if (aiFetch) {
    const resp = await aiFetch({ url, method: 'POST', headers: payload.headers, body: payload.body, timeoutMs });
    return { ok: resp.ok, status: resp.status, body: resp.body || '', contentType: extractContentType(resp.headers) };
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const onAbort = () => controller.abort();
  if (signal) signal.addEventListener('abort', onAbort);
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
    if (signal) signal.removeEventListener('abort', onAbort);
  }
}

interface GeminiResponse {
  candidates?: Array<{
    content?: {
      parts?: Array<{ text?: string }>;
    };
    finishReason?: string;
  }>;
  error?: { message?: string; code?: number };
}

/** Đọc danh sách model từ VITE_GEMINI_MODELS hoặc dùng fallback mặc định */
function resolveModelList(): string[] {
  const env = (import.meta as unknown as Record<string, Record<string, string>>).env ?? {};
  // FIX: Hỗ trợ cả VITE_GEMINI_MODELS (mới) và VITE_GEMINI_MODEL (cũ)
  const fromEnv = env.VITE_GEMINI_MODELS ?? env.VITE_GEMINI_MODEL ?? '';
  if (fromEnv.trim()) {
    return fromEnv.split(',').map(m => m.trim()).filter(Boolean);
  }
  return FALLBACK_MODELS;
}

export class GeminiProvider implements LLMProvider {
  readonly id = 'gemini';
  readonly label = 'Gemini (2.0 Flash)';
  readonly supportsJsonMode = false;

  private readonly apiKey: string;
  private readonly metrics: ProviderMetricsTracker;
  private readonly modelList: string[];

  constructor(metrics: ProviderMetricsTracker) {
    const env = (import.meta as unknown as Record<string, Record<string, string>>).env ?? {};
    this.apiKey = env.VITE_GEMINI_API_KEY ?? '';
    this.metrics = metrics;
    this.modelList = resolveModelList();
  }

  async generate(prompt: string, options: GenerateOptions = {}): Promise<string> {
    if (!this.apiKey) throw new ProviderError('auth_error', this.id, 'VITE_GEMINI_API_KEY not set');

    const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT;
    const start = Date.now();
    const systemPrompt = options.systemPrompt ?? 'You are a helpful security assistant.';

    let lastError: ProviderError | null = null;

    for (const model of this.modelList) {
      const body = {
        system_instruction: { parts: [{ text: systemPrompt }] },
        contents: [
          { role: 'user', parts: [{ text: prompt }] },
        ],
        generationConfig: {
          temperature: 0.7,
          maxOutputTokens: options.maxTokens ?? 1024,
        },
      };

      try {
        const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${this.apiKey}`;
        const headers = { 'Content-Type': 'application/json' };
        const res = await fetchJson(url, { headers, body: JSON.stringify(body) }, timeoutMs, options.signal);
        const latency = Date.now() - start;

        if (res.status === 429) {
          this.metrics.recordFailure(this.id, latency);
          throw new ProviderError('rate_limit', this.id, 'Rate limit exceeded', 429);
        }

        // FIX: 404 = model không tồn tại → thử model tiếp theo
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

        let data: GeminiResponse | null = null;
        try {
          data = res.body ? JSON.parse(res.body) : null;
        } catch {
          this.metrics.recordFailure(this.id, latency);
          throw new ProviderError('bad_request', this.id, 'Invalid JSON response', res.status);
        }

        // Kiểm tra lỗi trong response body (Gemini trả về 200 nhưng có error field)
        if (data?.error) {
          const code = data.error.code ?? 0;
          if (code === 404 || code === 400) {
            lastError = new ProviderError('bad_request', this.id, `Model "${model}" error: ${data.error.message}`, code);
            continue;
          }
          throw new ProviderError('bad_request', this.id, data.error.message ?? 'Gemini API error', code);
        }

        const text = data?.candidates?.[0]?.content?.parts?.[0]?.text ?? '';
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
    throw lastError ?? new ProviderError('bad_request', this.id, 'All Gemini models unavailable');
  }

  async health(): Promise<ProviderHealth> {
    return this.metrics.getHealth(this.id, !this.apiKey);
  }

  async estimateCostOrQuota(): Promise<number> {
    // Gemini 2.0 Flash free tier: 15 RPM, 1M TPM
    return this.apiKey ? 6_000 : 0;
  }
}
