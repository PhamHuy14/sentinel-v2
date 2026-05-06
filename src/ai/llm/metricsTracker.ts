/**
 * Provider Metrics Tracker (Trình theo dõi chỉ số của nhà cung cấp)
 *
 * Theo dõi cho từng nhà cung cấp: lịch sử độ trễ, số lượng lỗi, trạng thái ngắt mạch (circuit-breaker).
 * Được sử dụng bởi các nhà cung cấp và bộ định tuyến để đánh giá điểm sức khỏe và ngắt mạch.
 */

import { ProviderHealth } from './types';

interface ProviderState {
  /** Tổng số lệnh gọi đã thực hiện */
  totalCalls: number;
  /** Tổng cộng độ trễ của các lệnh gọi thành công */
  successLatencySum: number;
  /** Số lượng lệnh gọi thành công */
  successCount: number;
  /** Cửa sổ theo dõi kết quả gần đây: true=thành công, false=thất bại */
  recentWindow: boolean[];
  /** Số lần thất bại liên tiếp dùng cho ngắt mạch */
  consecutiveFailures: number;
  /** Trạng thái mạch có đang mở (ngắt) hay không */
  circuitOpen: boolean;
  /** Dấu thời gian khi mạch bị mở (ngắt) */
  circuitOpenAt: number;
}

const WINDOW_SIZE = 20; // N lệnh gọi gần nhất để tính toán tỷ lệ lỗi

export class ProviderMetricsTracker {
  private readonly states = new Map<string, ProviderState>();
  private readonly circuitBreakerThreshold: number;
  private readonly circuitResetMs: number;

  constructor(circuitBreakerThreshold = 5, circuitResetMs = 60_000) {
    this.circuitBreakerThreshold = circuitBreakerThreshold;
    this.circuitResetMs = circuitResetMs;
  }

  private getOrCreate(id: string): ProviderState {
    if (!this.states.has(id)) {
      this.states.set(id, {
        totalCalls: 0,
        successLatencySum: 0,
        successCount: 0,
        recentWindow: [],
        consecutiveFailures: 0,
        circuitOpen: false,
        circuitOpenAt: 0,
      });
    }
    return this.states.get(id)!;
  }

  recordSuccess(id: string, latencyMs: number): void {
    const s = this.getOrCreate(id);
    s.totalCalls++;
    s.successCount++;
    s.successLatencySum += latencyMs;
    s.consecutiveFailures = 0;
    // Tự động đóng mạch (circuit) khi thành công
    if (s.circuitOpen) s.circuitOpen = false;
    s.recentWindow.push(true);
    if (s.recentWindow.length > WINDOW_SIZE) s.recentWindow.shift();
  }

  recordFailure(id: string, _latencyMs: number): void {
    const s = this.getOrCreate(id);
    s.totalCalls++;
    s.consecutiveFailures++;
    s.recentWindow.push(false);
    if (s.recentWindow.length > WINDOW_SIZE) s.recentWindow.shift();

    // Kích hoạt ngắt mạch (circuit breaker)
    if (s.consecutiveFailures >= this.circuitBreakerThreshold) {
      s.circuitOpen = true;
      s.circuitOpenAt = Date.now();
    }
  }

  /**
   * Trả về sức khỏe hiện tại của một nhà cung cấp.
   * @param id - id của nhà cung cấp
   * @param noKey - nếu true, nhà cung cấp không có API key → đánh dấu là không khả dụng
   */
  getHealth(id: string, noKey = false): ProviderHealth {
    const s = this.getOrCreate(id);

    // Tự động thiết lập lại mạch (circuit) sau thời gian chờ (cooldown)
    if (s.circuitOpen && Date.now() - s.circuitOpenAt > this.circuitResetMs) {
      s.circuitOpen = false;
      s.consecutiveFailures = 0;
    }

    if (noKey) {
      return { score: 0, remainingQuota: 0, avgLatencyMs: 9999, recentErrorRate: 1, circuitOpen: true };
    }

    const recentErrors = s.recentWindow.filter(v => !v).length;
    const recentTotal  = s.recentWindow.length || 1;
    const recentErrorRate = recentErrors / recentTotal;

    const avgLatencyMs = s.successCount > 0
      ? s.successLatencySum / s.successCount
      : 3_000; // giả định 3s nếu chưa có dữ liệu

    // Điểm sức khỏe: phạt dựa trên tỷ lệ lỗi và độ trễ
    const latencyPenalty = Math.min(1, avgLatencyMs / 15_000); // 15s = cực kỳ tệ
    const score = Math.max(0, 1 - recentErrorRate * 0.6 - latencyPenalty * 0.4);

    return {
      score,
      remainingQuota: s.circuitOpen ? 0 : 1, // trừu tượng; hạn mức nằm trong estimateCostOrQuota
      avgLatencyMs,
      recentErrorRate,
      circuitOpen: s.circuitOpen,
    };
  }

  /** Trả về true nếu mạch (circuit) hiện đang mở (và chưa hết thời gian chờ). */
  isCircuitOpen(id: string): boolean {
    const s = this.states.get(id);
    if (!s) return false;
    if (s.circuitOpen && Date.now() - s.circuitOpenAt > this.circuitResetMs) {
      s.circuitOpen = false;
      s.consecutiveFailures = 0;
    }
    return s.circuitOpen;
  }

  /** Ảnh chụp nhanh (Snapshot) trạng thái tất cả các nhà cung cấp (dành cho mục đích quan sát/log). */
  snapshot(): Record<string, ProviderHealth & { totalCalls: number }> {
    const result: Record<string, ProviderHealth & { totalCalls: number }> = {};
    for (const [id, s] of this.states) {
      result[id] = { ...this.getHealth(id), totalCalls: s.totalCalls };
    }
    return result;
  }
}
