/**
 * Sanitizer — lớp bảo mật trước khi bất kỳ prompt nào được gửi đến API LLM bên ngoài
 *
 * 1. Che giấu (redact) các secret / token / credential
 * 2. Áp dụng các biện pháp bảo vệ cơ bản chống lại prompt-injection
 * 3. Cắt xén (truncate) để phù hợp với ngân sách token
 */

// ── Che giấu dữ liệu nhạy cảm (Redaction) ──────────────────────────────────────────────────────────────────

/**
 * Các pattern trông giống như secret.
 * Chúng ta thay thế chúng bằng một placeholder an toàn để chúng không bao giờ được gửi ra bên ngoài.
 */
const REDACT_PATTERNS: Array<{ label: string; pattern: RegExp }> = [
  // Token Bearer / API chung
  { label: 'BEARER_TOKEN',    pattern: /Bearer\s+[A-Za-z0-9._~+/-]+=*/gi },
  // Key dạng OpenAI
  { label: 'OPENAI_KEY',      pattern: /sk-[A-Za-z0-9]{20,}/g },
  // Key dạng Groq / together (gsk_...)
  { label: 'GROQ_KEY',        pattern: /gsk_[A-Za-z0-9]{20,}/g },
  // Token HuggingFace (hf_...)
  { label: 'HF_TOKEN',        pattern: /hf_[A-Za-z0-9]{20,}/g },
  // Secret chung trong gán giá trị KEY=VALUE, "key": "value"
  {
    label: 'ENV_SECRET',
    pattern: /(?:api[_-]?key|secret|token|password|passwd|pwd|auth)[=:\s"']+[A-Za-z0-9._~+/-]{8,}/gi,
  },
  // Access key AWS
  { label: 'AWS_KEY',         pattern: /AKIA[0-9A-Z]{16}/g },
  // Private key header
  { label: 'PRIVATE_KEY',     pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g },
  // Địa chỉ email (PII)
  { label: 'EMAIL',           pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g },
  // Dải IPv4 nội bộ (nguy cơ rò rỉ thấp, giữ lại IP công cộng)
  { label: 'PRIVATE_IP',      pattern: /\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b/g },
];

export interface RedactResult {
  text: string;
  redactedCount: number;
  labels: string[];
}

export function redactSecrets(input: string): RedactResult {
  let text = input;
  let redactedCount = 0;
  const labels: string[] = [];

  for (const { label, pattern } of REDACT_PATTERNS) {
    const before = text;
    text = text.replace(pattern, `[REDACTED:${label}]`);
    if (text !== before) {
      redactedCount++;
      labels.push(label);
    }
  }

  return { text, redactedCount, labels };
}

// ── Rào chắn bảo vệ Prompt injection ─────────────────────────────────────────────────

/**
 * Các cụm từ injection phổ biến cố gắng ghi đè hướng dẫn hệ thống.
 * Chúng ta sẽ loại bỏ hoặc làm mất hiệu lực chúng trước khi chuyển tiếp.
 */
const INJECTION_PATTERNS: RegExp[] = [
  /ignore\s+(?:all\s+)?(?:previous|prior|above|system)\s+instructions?/gi,
  /you\s+are\s+now\s+(?:a\s+)?(?:new\s+)?(?:AI|assistant|bot|DAN)/gi,
  /disregard\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?)/gi,
  /\[\s*system\s*\]/gi,
  /\[\s*INST\s*\]/gi,
  /<\|system\|>/gi,
  /<\|im_start\|>\s*system/gi,
  /###\s*(?:SYSTEM|INSTRUCTION|NEW PROMPT)/gi,
  /JAILBREAK/gi,
  /DAN\s+MODE/gi,
];

export function guardInjection(input: string): { text: string; injectionDetected: boolean } {
  let text = input;
  let injectionDetected = false;

  for (const pattern of INJECTION_PATTERNS) {
    if (pattern.test(text)) {
      injectionDetected = true;
      text = text.replace(pattern, '[BLOCKED]');
    }
  }

  return { text, injectionDetected };
}

// ── Ngân sách Token (Token budget) ───────────────────────────────────────────────────────────────

/**
 * Ước lượng rất thô: 1 token ≈ 4 ký tự.
 * Điều này giúp tránh tải một tokenizer đầy đủ cho context trình duyệt/Electron.
 */
export function estimateTokens(text: string): number {
  return Math.ceil(text.length / 4);
}

export function truncateToTokenBudget(text: string, maxTokens: number): string {
  const maxChars = maxTokens * 4;
  if (text.length <= maxChars) return text;
  return text.slice(0, maxChars) + '\n[... truncated for length ...]';
}

// ── Luồng xử lý làm sạch tổng hợp (Combined sanitize pipeline) ─────────────────────────────────────────────────
export interface SanitizeResult {
  prompt: string;
  warnings: string[];
}

export function sanitizePrompt(raw: string, maxInputTokens: number): SanitizeResult {
  const warnings: string[] = [];

  // Bước 1: che giấu secret
  const redacted = redactSecrets(raw);
  if (redacted.redactedCount > 0) {
    warnings.push(`Đã che giấu ${redacted.redactedCount} mẫu dữ liệu nhạy cảm: ${redacted.labels.join(', ')}`);
  }

  // Bước 2: bảo vệ chống injection
  const guarded = guardInjection(redacted.text);
  if (guarded.injectionDetected) {
    warnings.push('Đã chặn nguy cơ prompt injection');
  }

  // Bước 3: cắt xén (truncate)
  const truncated = truncateToTokenBudget(guarded.text, maxInputTokens);
  if (truncated !== guarded.text) {
    warnings.push(`Đã cắt xén prompt còn ${maxInputTokens} tokens`);
  }

  return { prompt: truncated, warnings };
}
