/**
 * Provider Metrics Tracker
 *
 * Tracks per-provider: latency history, error counts, circuit-breaker state.
 * Used by providers and the router for health scoring and circuit-breaking.
 */

import { ProviderHealth } from './types.js';

interface ProviderState {
  /** Total calls made */
  totalCalls: number;
  /** Running sum of successful call latencies */
  successLatencySum: number;
  /** Count of successful calls */
  successCount: number;
  /** Recent window of outcomes: true=success, false=failure */
  recentWindow: boolean[];
  /** Consecutive failure count for circuit breaker */
  consecutiveFailures: number;
  /** Whether circuit breaker is open */
  circuitOpen: boolean;
  /** Timestamp when circuit was opened */
  circuitOpenAt: number;
}

const WINDOW_SIZE = 20; // last N calls for error-rate calculation

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
    // Auto-close circuit on success
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

    // Trip circuit breaker
    if (s.consecutiveFailures >= this.circuitBreakerThreshold) {
      s.circuitOpen = true;
      s.circuitOpenAt = Date.now();
    }
  }

  /**
   * Returns current health for a provider.
   * @param id - provider id
   * @param noKey - if true, provider has no API key → mark as unavailable
   */
  getHealth(id: string, noKey = false): ProviderHealth {
    const s = this.getOrCreate(id);

    // Auto-reset circuit after cooldown
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
      : 3_000; // assume 3s if no data yet

    // Health score: penalise error rate and latency
    const latencyPenalty = Math.min(1, avgLatencyMs / 15_000); // 15s = max bad
    const score = Math.max(0, 1 - recentErrorRate * 0.6 - latencyPenalty * 0.4);

    return {
      score,
      remainingQuota: s.circuitOpen ? 0 : 1, // abstract; quota is in estimateCostOrQuota
      avgLatencyMs,
      recentErrorRate,
      circuitOpen: s.circuitOpen,
    };
  }

  /** Returns true if the circuit is currently open (and cooldown not expired). */
  isCircuitOpen(id: string): boolean {
    const s = this.states.get(id);
    if (!s) return false;
    if (s.circuitOpen && Date.now() - s.circuitOpenAt > this.circuitResetMs) {
      s.circuitOpen = false;
      s.consecutiveFailures = 0;
    }
    return s.circuitOpen;
  }

  /** Snapshot of all provider states (for observability). */
  snapshot(): Record<string, ProviderHealth & { totalCalls: number }> {
    const result: Record<string, ProviderHealth & { totalCalls: number }> = {};
    for (const [id, s] of this.states) {
      result[id] = { ...this.getHealth(id), totalCalls: s.totalCalls };
    }
    return result;
  }
}
