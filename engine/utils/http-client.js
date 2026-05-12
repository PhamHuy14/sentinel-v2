const { fetch, Agent } = require('undici');

// Max response body size (1 MB) — prevents memory bloat on large binary downloads
const MAX_BODY_BYTES = 1_048_576;

class ScannerHttpClient {
  constructor(options = {}) {
    this.timeoutMs        = options.timeoutMs        || 8000;
    this.maxRetries       = options.maxRetries       ?? 1;
    this.concurrencyLimit = options.concurrency      ?? 12;
    this.rejectUnauthorized = options.rejectUnauthorized !== false;
    this.requestDelayMs   = options.requestDelayMs   || 0;
    this.validateUrl      = options.validateUrl      || null;

    // Shared connection pool — reuse TCP connections across requests (big speed win)
    this.dispatcher = new Agent({
      connect: { rejectUnauthorized: this.rejectUnauthorized },
      connections:     20,   // max simultaneous connections to same host
      pipelining:       1,
      keepAliveTimeout: 10_000,
    });

    this.activeRequests = 0;
    this.queue          = [];

    // Per-URL response cache (text + status) for this scan session
    // Prevents re-fetching the same URL during crawl + fuzz phases
    this._cache = new Map();
  }

  // ── Queue management ─────────────────────────────────────────
  async _processQueue() {
    if (this.activeRequests >= this.concurrencyLimit || this.queue.length === 0) return;
    this.activeRequests++;
    const task = this.queue.shift();
    try {
      await task.fn();
    } finally {
      this.activeRequests--;
      if (this.requestDelayMs > 0) {
        setTimeout(() => this._processQueue(), this.requestDelayMs);
      } else {
        setImmediate(() => this._processQueue());
      }
    }
  }

  enqueue(fn) {
    return new Promise((resolve, reject) => {
      this.queue.push({
        fn: async () => { try { resolve(await fn()); } catch (e) { reject(e); } },
      });
      this._processQueue();
    });
  }

  // ── Core request ─────────────────────────────────────────────
  async request(url, options = {}) {
    // GET-only cache lookup (skip for mutation methods)
    const method = (options.method || 'GET').toUpperCase();
    const cacheKey = method === 'GET' ? url : null;
    if (cacheKey && this._cache.has(cacheKey)) {
      return this._cache.get(cacheKey);
    }

    let attempt = 0;

    const doRequest = async () => {
      const controller = new AbortController();
      const timeoutId  = setTimeout(() => controller.abort(), this.timeoutMs);

      // Support external abort signal (for stopScan)
      if (options.signal) {
        options.signal.addEventListener('abort', () => controller.abort(), { once: true });
      }

      try {
        let currentUrl = url;
        const shouldFollow = options.redirect !== 'manual';
        const maxRedirects = options.maxRedirects ?? 5;
        if (this.validateUrl) await this.validateUrl(currentUrl);
        const startTime = performance.now();
        let response;
        for (let redirects = 0; redirects <= maxRedirects; redirects++) {
          response = await fetch(currentUrl, {
            ...options,
            dispatcher: this.dispatcher,
            signal:     controller.signal,
            redirect:   'manual',
          });

          const location = response.headers.get('location');
          const isRedirect = response.status >= 300 && response.status < 400 && location;
          if (!shouldFollow || !isRedirect) break;
          if (redirects === maxRedirects) throw new Error(`Too many redirects: ${url}`);

          const nextUrl = new URL(location, currentUrl).toString();
          if (this.validateUrl) await this.validateUrl(nextUrl);
          currentUrl = nextUrl;
        }
        clearTimeout(timeoutId);

        // Read body with size cap
        const reader = response.body;
        let text = '';
        if (reader) {
          const chunks = [];
          let total    = 0;
          for await (const chunk of reader) {
            total += chunk.length;
            if (total > MAX_BODY_BYTES) { chunks.push(chunk.slice(0, MAX_BODY_BYTES - (total - chunk.length))); break; }
            chunks.push(chunk);
          }
          text = Buffer.concat(chunks).toString('utf8');
        }

        const timeMs = Math.round(performance.now() - startTime);
        const result = { response, text, finalUrl: response.url || currentUrl, timeMs };

        if (cacheKey) this._cache.set(cacheKey, result);
        return result;
      } catch (error) {
        clearTimeout(timeoutId);
        throw error;
      }
    };

    while (attempt <= this.maxRetries) {
      try {
        return await this.enqueue(doRequest);
      } catch (error) {
        attempt++;
        const isRetryable =
          error.name === 'AbortError' ||
          error.message?.includes('ECONNREFUSED') ||
          error.message?.includes('ENOTFOUND')    ||
          error.message?.includes('ETIMEDOUT')    ||
          error.message?.includes('fetch failed');

        if (!isRetryable || attempt > this.maxRetries) {
          if (error.name === 'AbortError') throw new Error(`Timeout/${this.timeoutMs}ms: ${url}`);
          throw new Error(`Request failed: ${error.message} (${url})`);
        }
        // Short linear backoff (500ms, 1000ms) — no exponential on scan tool
        await new Promise(r => setTimeout(r, 500 * attempt));
      }
    }
  }

  // Invalidate cache (e.g. after auth change)
  clearCache() { this._cache.clear(); }

  // Destroy connection pool
  async destroy() {
    try { await this.dispatcher.destroy(); } catch {}
  }
}

module.exports = { ScannerHttpClient };
