/**
 * OpenRouter Provider Adapter (Adapter cho nhà cung cấp OpenRouter)
 *
 * Gói miễn phí: https://openrouter.ai
 * Mô hình: meta-llama/llama-3.3-70b-instruct:free (chất lượng cao, miễn phí)
 * Bien moi truong: OPENROUTER_API_KEY (doc trong Electron main process)
 *
 * FIX v2.1:
 *  - Đổi model mặc định: llama-3.1-8b-instruct:free → llama-3.3-70b-instruct:free
 *  - Sửa tên env var: VITE_OPENROUTER_MODEL → VITE_OPENROUTER_MODELS (khớp với .env)
 *  - Hỗ trợ danh sách model fallback (comma-separated)
 *  - Thử model tiếp theo khi nhận 404 (model không tồn tại)
 */

import { ProviderMetricsTracker } from '../metricsTracker.js';
import {
    GenerateOptions,
    LLMProvider,
    ProviderError,
    ProviderHealth,
} from '../types';

const OPENROUTER_API_URL = 'https://openrouter.ai/api/v1/chat/completions';

// FIX: Danh sách model free tier hiện có trên OpenRouter (2025)
const FALLBACK_MODELS = [
  'meta-llama/llama-3.3-70b-instruct:free',   // Tốt nhất hiện có, miễn phí
  'meta-llama/llama-3.1-8b-instruct:free',     // Fallback nhỏ hơn
  'mistralai/mistral-7b-instruct:free',         // Fallback Mistral
  'google/gemma-3-27b-it:free',                 // Fallback Gemma
];

const DEFAULT_TIMEOUT = 20_000;

type AiFetch = (payload: {
  providerId: 'openrouter';
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
    const resp = await aiFetch({ providerId: 'openrouter', url, method: 'POST', headers: payload.headers, body: payload.body, timeoutMs });
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

/** Đọc danh sách model từ VITE_OPENROUTER_MODELS hoặc dùng fallback mặc định */
function resolveModelList(): string[] {
  // FIX: Hỗ trợ cả VITE_OPENROUTER_MODELS (mới) và VITE_OPENROUTER_MODEL (cũ)
  const fromEnv = import.meta.env.VITE_OPENROUTER_MODELS ?? import.meta.env.VITE_OPENROUTER_MODEL ?? '';
  if (fromEnv.trim()) {
    return fromEnv.split(',').map((m: string) => m.trim()).filter(Boolean);
  }
  return FALLBACK_MODELS;
}

export class OpenRouterProvider implements LLMProvider {
  readonly id = 'openrouter';
  readonly label = 'OpenRouter (Llama-3.3 70B Free)';
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

    const headers = {
      'Content-Type': 'application/json',
      'HTTP-Referer': 'https://sentinel.local',
      'X-Title': 'SENTINEL OWASP Assistant',
    };

    let lastError: ProviderError | null = null;

    for (const model of this.modelList) {
      const body = {
        model,
        messages: [
          { role: 'system', content: options.systemPrompt ?? 'You are a helpful security assistant.' },
          { role: 'user', content: prompt },
        ],
        max_tokens: options.maxTokens ?? 1024,
        temperature: 0.7,
        ...(options.jsonMode ? { response_format: { type: 'json_object' } } : {}),
      };

      try {
        const canStream = false;
        const res = canStream
          ? await streamOpenAiCompletion(OPENROUTER_API_URL, headers, body, timeoutMs, options.onToken!, options.signal)
          : await fetchJson(OPENROUTER_API_URL, { headers, body: JSON.stringify(body) }, timeoutMs, options.signal);
        const latency = Date.now() - start;

        if (res.status === 429) {
          this.metrics.recordFailure(this.id, latency);
          throw new ProviderError('rate_limit', this.id, 'Rate limit exceeded', 429);
        }
        if (res.status === 401 || res.status === 403) {
          this.metrics.recordFailure(this.id, latency);
          throw new ProviderError('auth_error', this.id, 'OPENROUTER_API_KEY not set or rejected', res.status);
        }

        // FIX: 404 nghĩa là model không tồn tại → thử model tiếp theo
        if (res.status === 404 || res.status === 400) {
          lastError = new ProviderError('bad_request', this.id, `Model "${model}" not available (HTTP ${res.status})`, res.status);
          continue;
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
          if (err.kind === 'rate_limit' || err.kind === 'auth_error') throw err;
          lastError = err;
          continue;
        }
        this.metrics.recordFailure(this.id, Date.now() - start);
        throw new ProviderError('unknown', this.id, String(err));
      }
    }

    this.metrics.recordFailure(this.id, Date.now() - start);
    throw lastError ?? new ProviderError('bad_request', this.id, 'All OpenRouter models unavailable');
  }

  async health(): Promise<ProviderHealth> {
    return this.metrics.getHealth(this.id, false);
  }

  async estimateCostOrQuota(): Promise<number> {
    return 8_000;
  }
}



