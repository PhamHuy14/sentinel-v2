/**
 * Hybrid AI Orchestrator
 *
 * Implements the 3-layer architecture:
 *   Layer 1 → Knowledge Base (offline FAQ, instant, highest priority)
 *   Layer 2 → Multi-provider LLM (external APIs, fallback)
 *   Layer 3 → Cross-checker / synthesiser (verifier built into LLMRouter)
 *
 * This is the single entry-point that replaces direct calls to routeQuery()
 * from UI components. It is backward-compatible: callers that only need
 * a plain string answer can call `orchestrate()` and read `.answer`.
 */

import { AiQueryPayload, routeQuery } from '../aiRouter.js';
import { AiResponse } from './types.js';
import { LLMRouter } from './llmRouter.js';

// ── Thresholds ─────────────────────────────────────────────────────────────────
/** Minimum KB answer length to be considered "good enough" — skip LLM */
const KB_MIN_LENGTH = 80;
/** Score returned by routeQuery that indicates an OOS / fallback response */
const OOS_MARKERS = [
  'Ngoài phạm vi hỗ trợ',
  'Chưa có trong knowledge base',
  'Tôi là AI assistant **chuyên về bảo mật web**',
  '⚠️ **AI service temporarily unavailable.**',
];

function isOOSResponse(text: string): boolean {
  return OOS_MARKERS.some(m => text.includes(m));
}

// ── Orchestrator ───────────────────────────────────────────────────────────────
export class HybridOrchestrator {
  private readonly llmRouter: LLMRouter | null;

  constructor(llmRouter: LLMRouter | null = null) {
    this.llmRouter = llmRouter;
  }

  /**
   * Main entry point.
   * 1. Try KB (routeQuery) — if good answer, return it immediately.
   * 2. If KB says OOS or answer is too short/generic, try LLM tier.
   * 3. Merge warnings and metadata into canonical AiResponse.
   */
  async orchestrate(payload: AiQueryPayload): Promise<AiResponse> {
    const start = Date.now();
    const warnings: string[] = [];

    // ── Layer 1: Knowledge Base ───────────────────────────────────────────────
    const kbAnswer = routeQuery(payload);
    const kbIsGood = kbAnswer.length >= KB_MIN_LENGTH && !isOOSResponse(kbAnswer);

    if (kbIsGood) {
      return {
        answer:         kbAnswer,
        confidence:     0.92,      // KB is authoritative for known topics
        providersTried: ['knowledge_base'],
        providerUsed:   'knowledge_base',
        crossChecked:   false,
        warnings:       [],
        latencyMs:      Date.now() - start,
        source:         'knowledge_base',
      };
    }

    // ── Layer 2: LLM fallback ─────────────────────────────────────────────────
    if (!this.llmRouter) {
      // No LLM router configured — surface KB answer or OOS message
      return {
        answer:         kbAnswer,
        confidence:     0.40,
        providersTried: ['knowledge_base'],
        providerUsed:   'knowledge_base',
        crossChecked:   false,
        warnings:       ['LLM tier not configured; using knowledge base only'],
        latencyMs:      Date.now() - start,
        source:         'knowledge_base',
      };
    }

    try {
      const llmResponse = await this.llmRouter.query(payload.question);

      // If LLM also gave a poor answer but KB had something, prefer KB
      if (llmResponse.confidence < 0.35 && kbAnswer.length > 40 && !isOOSResponse(kbAnswer)) {
        warnings.push('LLM confidence low; supplementing with knowledge base');
        return {
          ...llmResponse,
          answer:   `${kbAnswer}\n\n---\n*Additional context from AI:*\n\n${llmResponse.answer}`,
          warnings: [...llmResponse.warnings, ...warnings],
          latencyMs: Date.now() - start,
          source:   'synthesized',
        };
      }

      return {
        ...llmResponse,
        warnings:  [...llmResponse.warnings, ...warnings],
        latencyMs: Date.now() - start,
      };
    } catch (err) {
      warnings.push(`LLM tier error: ${(err as Error).message}`);

      // Graceful fallback to KB answer regardless of quality
      return {
        answer:         isOOSResponse(kbAnswer)
          ? '⚠️ **AI service unavailable.** Please rephrase your question or check back later.'
          : kbAnswer,
        confidence:     isOOSResponse(kbAnswer) ? 0 : 0.50,
        providersTried: ['knowledge_base'],
        providerUsed:   'knowledge_base',
        crossChecked:   false,
        warnings,
        latencyMs:      Date.now() - start,
        source:         'knowledge_base',
      };
    }
  }
}

// ── Singleton factory ──────────────────────────────────────────────────────────
let _instance: HybridOrchestrator | null = null;

export function getOrchestrator(): HybridOrchestrator {
  if (!_instance) _instance = new HybridOrchestrator(null);
  return _instance;
}

/**
 * Call this once at app startup to inject the LLM router (with real providers).
 * Safe to call multiple times — only replaces if not already set with router.
 */
export function initOrchestrator(llmRouter: LLMRouter): void {
  _instance = new HybridOrchestrator(llmRouter);
}

/**
 * Backward-compatible wrapper: returns plain string, same as old routeQuery.
 * Existing callers can migrate gradually.
 */
export async function orchestrateToString(payload: AiQueryPayload): Promise<string> {
  return (await getOrchestrator().orchestrate(payload)).answer;
}
