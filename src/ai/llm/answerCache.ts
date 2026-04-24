/**
 * Answer Cache
 *
 * LRU-style in-memory cache for AI responses.
 * Keyed by a normalized question hash; entries expire after TTL.
 */

export interface CacheEntry {
  answer: string;
  confidence: number;
  providerUsed: string;
  crossChecked: boolean;
  createdAt: number;
}

export class AnswerCache {
  private readonly store = new Map<string, CacheEntry>();
  private readonly ttlMs: number;
  private readonly maxSize: number;

  constructor(ttlMs = 5 * 60_000, maxSize = 200) {
    this.ttlMs  = ttlMs;
    this.maxSize = maxSize;
  }

  /** Simple deterministic key: lowercase + collapse whitespace */
  static makeKey(question: string): string {
    return question.toLowerCase().replace(/\s+/g, ' ').trim();
  }

  get(question: string): CacheEntry | null {
    const key = AnswerCache.makeKey(question);
    const entry = this.store.get(key);
    if (!entry) return null;

    // Expired?
    if (Date.now() - entry.createdAt > this.ttlMs) {
      this.store.delete(key);
      return null;
    }
    // Move to end (LRU touch)
    this.store.delete(key);
    this.store.set(key, entry);
    return entry;
  }

  set(question: string, entry: Omit<CacheEntry, 'createdAt'>): void {
    const key = AnswerCache.makeKey(question);

    // Evict oldest if at capacity
    if (this.store.size >= this.maxSize) {
      const firstKey = this.store.keys().next().value;
      if (firstKey !== undefined) this.store.delete(firstKey);
    }

    this.store.set(key, { ...entry, createdAt: Date.now() });
  }

  /** Remove all expired entries */
  purgeExpired(): void {
    const now = Date.now();
    for (const [key, entry] of this.store) {
      if (now - entry.createdAt > this.ttlMs) this.store.delete(key);
    }
  }

  get size(): number {
    return this.store.size;
  }

  clear(): void {
    this.store.clear();
  }
}
