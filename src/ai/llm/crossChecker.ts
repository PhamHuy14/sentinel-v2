/**
 * Cross-Checker
 *
 * Compares two answers from independent providers and decides:
 *  - Are they in agreement (high overlap)?
 *  - Do they contradict each other?
 *  - What confidence level should be assigned?
 *
 * Uses heuristics only (no external embedding call) so it works offline:
 *  1. Token-overlap Jaccard similarity
 *  2. Contradiction signal words
 *  3. Policy / safety keyword check
 */

export interface CrossCheckResult {
  /** Final chosen answer */
  chosenAnswer: string;
  /** Which provider's answer was chosen: 'primary' | 'secondary' | 'synthesized' */
  chosenFrom: 'primary' | 'secondary' | 'synthesized';
  /** 0–1 confidence after cross-check */
  confidence: number;
  /** Human-readable reason */
  rationale: string;
  /** True when answers agreed (no contradiction detected) */
  agreed: boolean;
}

// ── Helpers ────────────────────────────────────────────────────────────────────

/** Basic text tokeniser: lowercase words ≥ 3 chars */
function tokenize(text: string): Set<string> {
  return new Set(
    text
      .toLowerCase()
      .replace(/[^\w\s]/g, ' ')
      .split(/\s+/)
      .filter(w => w.length >= 3),
  );
}

/** Jaccard similarity between two token sets */
function jaccard(a: Set<string>, b: Set<string>): number {
  if (a.size === 0 && b.size === 0) return 1;
  let intersection = 0;
  for (const t of a) if (b.has(t)) intersection++;
  const union = a.size + b.size - intersection;
  return union === 0 ? 0 : intersection / union;
}

/** Check if text B explicitly contradicts text A via negation signals */
const CONTRADICTION_SIGNALS = [
  /\bnot\b.{0,20}\b(safe|secure|recommended|correct|true)\b/i,
  /\bincorrect\b/i,
  /\bwrong\b/i,
  /\bfalse\b.{0,20}\b(statement|claim|information)\b/i,
  /\bnever\b.{0,20}\b(do|use|trust)\b/i,
  /\bdo not\b.{0,20}\b(trust|use|follow)\b/i,
  /\bopposite\b/i,
  /\bcontradicts\b/i,
  /\bdisagree\b/i,
];

function hasContradictionSignal(text: string): boolean {
  return CONTRADICTION_SIGNALS.some(p => p.test(text));
}

/** Very basic safety / policy check: returns flagged phrases */
const UNSAFE_PATTERNS: RegExp[] = [
  /exploit\s+this\s+vulnerability/i,
  /step[- ]by[- ]step\s+attack/i,
  /write\s+malware/i,
  /create\s+(?:a\s+)?(?:virus|worm|trojan|backdoor)/i,
  /bypass\s+(?:authentication|security|firewall)\s+completely/i,
];

function hasUnsafeContent(text: string): boolean {
  return UNSAFE_PATTERNS.some(p => p.test(text));
}

// ── Main cross-check ───────────────────────────────────────────────────────────

/**
 * AGREEMENT thresholds:
 *   Jaccard ≥ 0.30 → treat as agreeing
 *   Jaccard < 0.10 → treat as contradicting
 */
const AGREE_THRESHOLD       = 0.30;
const CONTRADICT_THRESHOLD  = 0.10;

export function crossCheck(primaryAnswer: string, secondaryAnswer: string): CrossCheckResult {
  const tokPrimary   = tokenize(primaryAnswer);
  const tokSecondary = tokenize(secondaryAnswer);
  const similarity   = jaccard(tokPrimary, tokSecondary);

  const primaryUnsafe   = hasUnsafeContent(primaryAnswer);
  const secondaryUnsafe = hasUnsafeContent(secondaryAnswer);

  // If primary is unsafe but secondary is not, prefer secondary
  if (primaryUnsafe && !secondaryUnsafe) {
    return {
      chosenAnswer: secondaryAnswer,
      chosenFrom: 'secondary',
      confidence: 0.55,
      rationale: 'Primary response flagged by safety check; using secondary',
      agreed: false,
    };
  }

  // Both unsafe — return synthesised disclaimer
  if (primaryUnsafe && secondaryUnsafe) {
    return {
      chosenAnswer:
        'I cannot provide information on that topic as it may assist with malicious activity. ' +
        'Please refer to OWASP guidelines for ethical security research.',
      chosenFrom: 'synthesized',
      confidence: 0.90,
      rationale: 'Both responses flagged unsafe; returning policy disclaimer',
      agreed: false,
    };
  }

  // High similarity → agreement
  if (similarity >= AGREE_THRESHOLD) {
    // Pick the longer, more detailed answer
    const chosen = primaryAnswer.length >= secondaryAnswer.length ? primaryAnswer : secondaryAnswer;
    const from   = chosen === primaryAnswer ? 'primary' : 'secondary';
    return {
      chosenAnswer: chosen,
      chosenFrom: from,
      confidence: Math.min(0.95, 0.70 + similarity * 0.5),
      rationale: `Providers agreed (Jaccard=${similarity.toFixed(2)}); chose ${from} (more detailed)`,
      agreed: true,
    };
  }

  // Potential contradiction
  const primaryContradicts   = hasContradictionSignal(primaryAnswer);
  const secondaryContradicts = hasContradictionSignal(secondaryAnswer);

  if (similarity < CONTRADICT_THRESHOLD || (primaryContradicts && secondaryContradicts)) {
    // Strong contradiction — synthesise a hedged response
    const synthesised =
      `**Note: Multiple sources gave different perspectives on this question.**\n\n` +
      `**Primary answer:**\n${primaryAnswer}\n\n` +
      `**Alternative view:**\n${secondaryAnswer}\n\n` +
      `*Please consult official OWASP documentation for authoritative guidance.*`;
    return {
      chosenAnswer: synthesised,
      chosenFrom: 'synthesized',
      confidence: 0.45,
      rationale: `Contradiction detected (Jaccard=${similarity.toFixed(2)}); synthesised hedged response`,
      agreed: false,
    };
  }

  // Partial overlap — prefer primary, note low confidence
  return {
    chosenAnswer: primaryAnswer,
    chosenFrom: 'primary',
    confidence: 0.55 + similarity * 0.3,
    rationale: `Partial overlap (Jaccard=${similarity.toFixed(2)}); defaulting to primary`,
    agreed: false,
  };
}
