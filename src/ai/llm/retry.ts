/**
 * Trình trợ giúp (helper) thử lại (retry) với thuật toán exponential backoff + jitter
 *
 * Cách sử dụng:
 *   const result = await withRetry(() => provider.generate(prompt), {
 *     maxRetries: 2,
 *     baseDelayMs: 300,
 *     maxDelayMs: 4_000,
 *     shouldRetry: (err) => err instanceof ProviderError && err.kind !== 'auth_error',
 *   });
 */

export interface RetryOptions {
  maxRetries: number;
  baseDelayMs: number;
  maxDelayMs: number;
  /**
   * Hàm đánh giá để quyết định xem một lỗi có đáng để thử lại hay không.
   * Mặc định là luôn thử lại.
   */
  shouldRetry?: (err: unknown, attempt: number) => boolean;
}

/** Mặc định: không thử lại đối với các lỗi xác thực (auth errors) */
function defaultShouldRetry(err: unknown): boolean {
  // Tránh phụ thuộc vòng (circular dep) — kiểm tra thuộc tính `kind` theo kiểu duck-typing
  const kind = (err as { kind?: string }).kind;
  return kind !== 'auth_error' && kind !== 'bad_request';
}

/**
 * Tính toán độ trễ với full jitter:
 *   delay = random(0, min(maxDelay, base * 2^attempt))
 */
function computeDelay(attempt: number, baseMs: number, maxMs: number): number {
  const exponential = baseMs * Math.pow(2, attempt);
  const capped      = Math.min(maxMs, exponential);
  return Math.random() * capped; // full jitter
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

export async function withRetry<T>(
  fn: () => Promise<T>,
  opts: RetryOptions,
): Promise<T> {
  const shouldRetry = opts.shouldRetry ?? defaultShouldRetry;
  let lastError: unknown;

  for (let attempt = 0; attempt <= opts.maxRetries; attempt++) {
    try {
      return await fn();
    } catch (err) {
      lastError = err;
      const isLast = attempt === opts.maxRetries;
      if (isLast || !shouldRetry(err, attempt)) {
        throw err;
      }
      const delay = computeDelay(attempt, opts.baseDelayMs, opts.maxDelayMs);
      await sleep(delay);
    }
  }

  // Sẽ không bao giờ chạy đến đây, nhưng viết để thỏa mãn TypeScript
  throw lastError;
}
