/**
 * Cross-Checker (Trình kiểm tra chéo)
 *
 * So sánh hai câu trả lời từ các nhà cung cấp độc lập và quyết định:
 *  - Chúng có đồng thuận không (mức độ trùng lặp cao)?
 *  - Chúng có mâu thuẫn với nhau không?
 *  - Mức độ tin cậy (confidence level) nào nên được gán?
 *
 * Chỉ sử dụng phương pháp heuristic (không gọi hàm embedding bên ngoài) để có thể hoạt động ngoại tuyến:
 *  1. Độ tương đồng Jaccard dựa trên mức độ trùng lặp token
 *  2. Các từ mang tín hiệu mâu thuẫn
 *  3. Kiểm tra từ khóa về chính sách / an toàn
 */

export interface CrossCheckResult {
  /** Câu trả lời được chọn cuối cùng */
  chosenAnswer: string;
  /** Câu trả lời được chọn từ nhà cung cấp nào: 'primary' | 'secondary' | 'synthesized' */
  chosenFrom: 'primary' | 'secondary' | 'synthesized';
  /** Độ tin cậy từ 0–1 sau khi kiểm tra chéo */
  confidence: number;
  /** Lý do (rationale) có thể đọc được bởi con người */
  rationale: string;
  /** True khi các câu trả lời đồng thuận (không phát hiện mâu thuẫn) */
  agreed: boolean;
}

// ── Trình trợ giúp (Helpers) ────────────────────────────────────────────────────────────────────

/** Trình token hóa văn bản cơ bản (Basic text tokeniser): viết thường các từ có ≥ 3 ký tự */
function tokenize(text: string): Set<string> {
  return new Set(
    text
      .toLowerCase()
      .replace(/[^\w\s]/g, ' ')
      .split(/\s+/)
      .filter(w => w.length >= 3),
  );
}

/** Độ tương đồng Jaccard giữa hai tập hợp token */
function jaccard(a: Set<string>, b: Set<string>): number {
  if (a.size === 0 && b.size === 0) return 1;
  let intersection = 0;
  for (const t of a) if (b.has(t)) intersection++;
  const union = a.size + b.size - intersection;
  return union === 0 ? 0 : intersection / union;
}

/** Kiểm tra xem văn bản B có mâu thuẫn rõ ràng với văn bản A thông qua các tín hiệu phủ định không */
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

/** Kiểm tra an toàn / chính sách ở mức rất cơ bản: trả về các cụm từ bị gắn cờ vi phạm */
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

// ── Kiểm tra chéo chính (Main cross-check) ───────────────────────────────────────────────────────────

/**
 * Ngưỡng ĐỒNG THUẬN (AGREEMENT thresholds):
 *   Jaccard ≥ 0.30 → coi như đồng thuận
 *   Jaccard < 0.10 → coi như mâu thuẫn
 */
const AGREE_THRESHOLD       = 0.30;
const CONTRADICT_THRESHOLD  = 0.10;

export function crossCheck(primaryAnswer: string, secondaryAnswer: string): CrossCheckResult {
  const tokPrimary   = tokenize(primaryAnswer);
  const tokSecondary = tokenize(secondaryAnswer);
  const similarity   = jaccard(tokPrimary, tokSecondary);

  const primaryUnsafe   = hasUnsafeContent(primaryAnswer);
  const secondaryUnsafe = hasUnsafeContent(secondaryAnswer);

  // Nếu primary không an toàn nhưng secondary an toàn, ưu tiên chọn secondary
  if (primaryUnsafe && !secondaryUnsafe) {
    return {
      chosenAnswer: secondaryAnswer,
      chosenFrom: 'secondary',
      confidence: 0.55,
      rationale: 'Primary response flagged by safety check; using secondary',
      agreed: false,
    };
  }

  // Cả hai đều không an toàn — trả về cảnh báo miễn trừ trách nhiệm được tổng hợp
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

  // Độ tương đồng cao → đồng thuận
  if (similarity >= AGREE_THRESHOLD) {
    // Chọn câu trả lời dài hơn, chi tiết hơn
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

  // Tiềm ẩn khả năng mâu thuẫn
  const primaryContradicts   = hasContradictionSignal(primaryAnswer);
  const secondaryContradicts = hasContradictionSignal(secondaryAnswer);

  if (similarity < CONTRADICT_THRESHOLD || (primaryContradicts && secondaryContradicts)) {
    // Mâu thuẫn mạnh — tổng hợp một câu trả lời phòng hờ (hedged response)
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

  // Trùng lặp một phần — ưu tiên primary, ghi nhận độ tin cậy thấp
  return {
    chosenAnswer: primaryAnswer,
    chosenFrom: 'primary',
    confidence: 0.55 + similarity * 0.3,
    rationale: `Partial overlap (Jaccard=${similarity.toFixed(2)}); defaulting to primary`,
    agreed: false,
  };
}
