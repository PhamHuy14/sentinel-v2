/**
 * Retry helper with exponential backoff + jitter
 *
 * Usage:
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
   * Predicate to decide whether a given error is worth retrying.
   * Defaults to always retry.
   */
  shouldRetry?: (err: unknown, attempt: number) => boolean;
}

/** Default: don't retry auth errors */
function defaultShouldRetry(err: unknown): boolean {
  // Avoid circular dep — check duck-typed `kind` property
  const kind = (err as { kind?: string }).kind;
  return kind !== 'auth_error' && kind !== 'bad_request';
}

/**
 * Compute delay with full jitter:
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

  // Should never reach here, but satisfies TypeScript
  throw lastError;
}
