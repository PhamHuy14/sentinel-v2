/**
 * Answer Cache (Bộ nhớ đệm câu trả lời)
 *
 * Bộ nhớ đệm trong RAM (in-memory) kiểu LRU (Least Recently Used) dành cho phản hồi của AI.
 * Sử dụng khóa (key) là mã băm (hash) của câu hỏi đã được chuẩn hóa; các mục sẽ hết hạn sau thời gian TTL.
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

  /** Khóa (key) đơn giản mang tính tất định: viết thường toàn bộ + gộp các khoảng trắng */
  static makeKey(question: string, context?: string): string {
    const base = question.toLowerCase().replace(/\s+/g, ' ').trim();
    if (!context) return base;
    const ctx = context.toLowerCase().replace(/\s+/g, ' ').trim();
    if (!ctx) return base;
    return `${base}::ctx-${AnswerCache.hashContext(ctx)}`;
  }

  private static hashContext(text: string): string {
    let hash = 5381;
    for (let i = 0; i < text.length; i++) {
      hash = ((hash << 5) + hash) + text.charCodeAt(i);
      hash |= 0;
    }
    return Math.abs(hash).toString(36);
  }

  get(question: string, context?: string): CacheEntry | null {
    const key = AnswerCache.makeKey(question, context);
    const entry = this.store.get(key);
    if (!entry) return null;

    // Đã hết hạn?
    if (Date.now() - entry.createdAt > this.ttlMs) {
      this.store.delete(key);
      return null;
    }
    // Di chuyển xuống cuối (chạm vào LRU - LRU touch)
    this.store.delete(key);
    this.store.set(key, entry);
    return entry;
  }

  set(question: string, entry: Omit<CacheEntry, 'createdAt'>, context?: string): void {
    const key = AnswerCache.makeKey(question, context);

    // Loại bỏ mục cũ nhất nếu đã đạt giới hạn dung lượng
    if (this.store.size >= this.maxSize) {
      const firstKey = this.store.keys().next().value;
      if (firstKey !== undefined) this.store.delete(firstKey);
    }

    this.store.set(key, { ...entry, createdAt: Date.now() });
  }

  /** Xóa bỏ tất cả các mục đã hết hạn */
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
