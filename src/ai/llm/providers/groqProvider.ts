/**
 * Groq Provider Adapter (Adapter cho nhà cung cấp Groq)
 *
 * Gói miễn phí: https://console.groq.com
 * Mô hình: llama-3.3-70b-versatile (nhanh, mạnh, miễn phí)
 * Biến môi trường: GROQ_API_KEY (đọc trong Electron main process)
 *
 * FIX v2.1:
 *  - Đổi DEFAULT_MODEL từ llama3-8b-8192 (deprecated) → llama-3.3-70b-versatile
 *  - Hỗ trợ đọc danh sách model từ VITE_GROQ_MODELS (comma-separated)
 *  - Tự động fallback sang model tiếp theo nếu model hiện tại bị lỗi 400/404
 */

import { ProviderMetricsTracker } from '../metricsTracker.js';
import {
    GenerateOptions,
    LLMProvider,
    ProviderError,
    ProviderHealth,
} from '../types';

const GROQ_API_URL = 'https://api.groq.com/openai/v1/chat/completions';

// FIX: Danh sách model fallback — llama3-8b-8192 đã bị Groq deprecated
const FALLBACK_MODELS = [
  'llama-3.3-70b-versatile',   // Tốt nhất, miễn phí, ĐỀ XUẤT
  'llama-3.1-70b-versatile',   // Fallback #1
  'llama3-70b-8192',           // Fallback #2 (tên cũ hơn nhưng vẫn hoạt động)
  'llama-3.1-8b-instant',      // Fallback #3 (nhỏ hơn nhưng siêu nhanh)
];

const DEFAULT_TIMEOUT = 15_000;

type AiFetch = (payload: {
  providerId: 'groq';
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

async function fetchJson(
  url: string,
  payload: { headers: Record<string, string>; body: string },
  timeoutMs: number,
  signal?: AbortSignal,
) {
  const aiFetch = getAiFetch();
  if (aiFetch) {
    const resp = await aiFetch({ providerId: 'groq', url, method: 'POST', headers: payload.headers, body: payload.body, timeoutMs });
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

async function streamOpenAiCompletion(
  url: string,
  headers: Record<string, string>,
  body: Record<string, unknown>,
  timeoutMs: number,
  onToken: (token: string) => void,
  signal?: AbortSignal,
): Promise<{ ok: boolean; status: number; text: string }>
{
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const onAbort = () => controller.abort();
  if (signal) signal.addEventListener('abort', onAbort);

  try {
    const res = await fetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify({ ...body, stream: true }),
      signal: controller.signal,
    });

    if (!res.ok) {
      const text = await res.text().catch(() => '');
      return { ok: false, status: res.status, text };
    }

    if (!res.body) {
      return { ok: false, status: res.status, text: '' };
    }

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    let full = '';

    // eslint-disable-next-line no-constant-condition
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop() ?? '';

      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed.startsWith('data:')) continue;
        const data = trimmed.slice(5).trim();
        if (data === '[DONE]') {
          return { ok: true, status: res.status, text: full };
        }
        try {
          const json = JSON.parse(data) as { choices?: { delta?: { content?: string } }[] };
          const delta = json.choices?.[0]?.delta?.content ?? '';
          if (delta) {
            full += delta;
            onToken(delta);
          }
        } catch {
          // ignore chunk parse errors
        }
      }
    }

    return { ok: true, status: res.status, text: full };
  } finally {
    clearTimeout(timer);
    if (signal) signal.removeEventListener('abort', onAbort);
  }
}

/** Đọc danh sách model từ env var VITE_GROQ_MODELS (comma-separated) hoặc dùng fallback mặc định */
function resolveModelList(): string[] {
  const fromEnv = import.meta.env.VITE_GROQ_MODELS ?? '';
  if (fromEnv.trim()) {
    return fromEnv.split(',').map((m: string) => m.trim()).filter(Boolean);
  }
  return FALLBACK_MODELS;
}

export class GroqProvider implements LLMProvider {
  readonly id = 'groq';
  readonly label = 'Groq (Llama-3.3 70B)';
  readonly supportsJsonMode = true;

  private readonly metrics: ProviderMetricsTracker;
  private readonly modelList: string[];

  constructor(metrics: ProviderMetricsTracker) {
    this.metrics = metrics;
    this.modelList = resolveModelList();
  }

  async generate(prompt: string, options: GenerateOptions = {}): Promise<string> {
    const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT;
    const start = Date.now();

    // FIX: Thử từng model trong danh sách, dừng khi thành công
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
        ...(options.jsonMode ? { response_format: { type: 'json_object' } } : {}),
      };

      try {
        const headers = {
          'Content-Type': 'application/json',
        };
        const canStream = false;
        const res = canStream
          ? await streamOpenAiCompletion(GROQ_API_URL, headers, body, timeoutMs, options.onToken!, options.signal)
          : await fetchJson(GROQ_API_URL, { headers, body: JSON.stringify(body) }, timeoutMs, options.signal);
        const latency = Date.now() - start;

        if (res.status === 429) {
          this.metrics.recordFailure(this.id, latency);
          throw new ProviderError('rate_limit', this.id, 'Rate limit exceeded', 429);
        }
        if (res.status === 401 || res.status === 403) {
          this.metrics.recordFailure(this.id, latency);
          throw new ProviderError('auth_error', this.id, 'GROQ_API_KEY not set or rejected', res.status);
        }

        // FIX: 400 hoặc 404 thường do model deprecated/không tồn tại → thử model tiếp theo
        if (res.status === 400 || res.status === 404) {
          lastError = new ProviderError('bad_request', this.id, `Model "${model}" unavailable (HTTP ${res.status})`, res.status);
          continue; // thử model tiếp theo
        }

        if (!res.ok) {
          this.metrics.recordFailure(this.id, latency);
          const kind = res.status >= 500 ? 'server_error' : 'bad_request';
          throw new ProviderError(kind, this.id, `HTTP ${res.status}`, res.status);
        }

        let text = '';
        if (canStream) {
          text = (res as { text: string }).text;
        } else {
          const fetchRes = res as { body: string; contentType: string };
          if (!shouldParseJson(fetchRes.body, fetchRes.contentType)) {
            this.metrics.recordFailure(this.id, latency);
            throw new ProviderError('bad_request', this.id, 'Non-JSON response', res.status);
          }

          let data: { choices?: { message?: { content?: string } }[] } | null = null;
          try {
            data = fetchRes.body ? JSON.parse(fetchRes.body) : null;
          } catch {
            this.metrics.recordFailure(this.id, latency);
            throw new ProviderError('bad_request', this.id, 'Invalid JSON response', res.status);
          }

          text = data?.choices?.[0]?.message?.content ?? '';
        }

        this.metrics.recordSuccess(this.id, latency);
        return text.trim();

      } catch (err) {
        if ((err as Error).name === 'AbortError') {
          this.metrics.recordFailure(this.id, timeoutMs);
          throw new ProviderError('timeout', this.id, 'Request timed out');
        }
        if (err instanceof ProviderError) {
          // Nếu là lỗi rate_limit hoặc auth → không thử tiếp
          if (err.kind === 'rate_limit' || err.kind === 'auth_error') throw err;
          // bad_request do model deprecated → thử tiếp
          lastError = err;
          continue;
        }
        this.metrics.recordFailure(this.id, Date.now() - start);
        throw new ProviderError('unknown', this.id, String(err));
      }
    }

    // Tất cả model đều thất bại
    this.metrics.recordFailure(this.id, Date.now() - start);
    throw lastError ?? new ProviderError('bad_request', this.id, 'All Groq models unavailable');
  }

  async health(): Promise<ProviderHealth> {
    return this.metrics.getHealth(this.id, false);
  }

  async estimateCostOrQuota(): Promise<number> {
    // Groq free tier: ~14.400 request/ngày cho llama-3.3-70b-versatile
    return 14_400;
  }
}


