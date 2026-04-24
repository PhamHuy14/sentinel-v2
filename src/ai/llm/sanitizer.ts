/**
 * Sanitizer — security layer before any prompt reaches an external LLM API
 *
 * 1. Redacts secrets / tokens / credentials
 * 2. Applies basic prompt-injection guardrails
 * 3. Truncates to token budget
 */

// ── Redaction ──────────────────────────────────────────────────────────────────

/**
 * Patterns that look like secrets.
 * We replace them with a safe placeholder so they are never sent externally.
 */
const REDACT_PATTERNS: Array<{ label: string; pattern: RegExp }> = [
  // Generic Bearer / API tokens
  { label: 'BEARER_TOKEN',    pattern: /Bearer\s+[A-Za-z0-9\-._~+/]+=*/gi },
  // OpenAI-style keys
  { label: 'OPENAI_KEY',      pattern: /sk-[A-Za-z0-9]{20,}/g },
  // Groq / together style keys (gsk_...)
  { label: 'GROQ_KEY',        pattern: /gsk_[A-Za-z0-9]{20,}/g },
  // HuggingFace tokens (hf_...)
  { label: 'HF_TOKEN',        pattern: /hf_[A-Za-z0-9]{20,}/g },
  // Generic secrets in assignments  KEY=VALUE, "key": "value"
  {
    label: 'ENV_SECRET',
    pattern: /(?:api[_-]?key|secret|token|password|passwd|pwd|auth)[=:\s"']+[A-Za-z0-9\-._~+/]{8,}/gi,
  },
  // AWS access keys
  { label: 'AWS_KEY',         pattern: /AKIA[0-9A-Z]{16}/g },
  // Private key headers
  { label: 'PRIVATE_KEY',     pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g },
  // Email addresses (PII)
  { label: 'EMAIL',           pattern: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g },
  // IPv4 private ranges (minimal leak risk, keep public IPs)
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

// ── Prompt injection guardrail ─────────────────────────────────────────────────

/**
 * Common injection phrases that try to override system instructions.
 * We strip or neuter them before forwarding.
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

// ── Token budget ───────────────────────────────────────────────────────────────

/**
 * Very rough approximation: 1 token ≈ 4 chars.
 * This avoids loading a full tokenizer for a browser/Electron context.
 */
export function estimateTokens(text: string): number {
  return Math.ceil(text.length / 4);
}

export function truncateToTokenBudget(text: string, maxTokens: number): string {
  const maxChars = maxTokens * 4;
  if (text.length <= maxChars) return text;
  return text.slice(0, maxChars) + '\n[... truncated for length ...]';
}

// ── Combined sanitize pipeline ─────────────────────────────────────────────────
export interface SanitizeResult {
  prompt: string;
  warnings: string[];
}

export function sanitizePrompt(raw: string, maxInputTokens: number): SanitizeResult {
  const warnings: string[] = [];

  // Step 1: redact secrets
  const redacted = redactSecrets(raw);
  if (redacted.redactedCount > 0) {
    warnings.push(`Redacted ${redacted.redactedCount} sensitive pattern(s): ${redacted.labels.join(', ')}`);
  }

  // Step 2: injection guard
  const guarded = guardInjection(redacted.text);
  if (guarded.injectionDetected) {
    warnings.push('Potential prompt injection blocked');
  }

  // Step 3: truncate
  const truncated = truncateToTokenBudget(guarded.text, maxInputTokens);
  if (truncated !== guarded.text) {
    warnings.push(`Prompt truncated to ${maxInputTokens} tokens`);
  }

  return { prompt: truncated, warnings };
}
