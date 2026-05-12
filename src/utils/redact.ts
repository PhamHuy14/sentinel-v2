const SECRET_PATTERNS: Array<[RegExp, string]> = [
  [/Bearer\s+[A-Za-z0-9._~+/-]+=*/gi, 'Bearer [REDACTED]'],
  [/(authorization\s*[:=]\s*)([^\s,;"']+)/gi, '$1[REDACTED]'],
  [/(cookie\s*[:=]\s*)([^;\n]+)/gi, '$1[REDACTED]'],
  [/(api[_-]?key|secret|token|password|passwd|pwd)(["'\s:=]+)([A-Za-z0-9._~+/-]{6,})/gi, '$1$2[REDACTED]'],
  [/sk-[A-Za-z0-9]{20,}/g, '[REDACTED:OPENAI_KEY]'],
  [/gsk_[A-Za-z0-9]{20,}/g, '[REDACTED:GROQ_KEY]'],
  [/hf_[A-Za-z0-9]{20,}/g, '[REDACTED:HF_TOKEN]'],
  [/AKIA[0-9A-Z]{16}/g, '[REDACTED:AWS_KEY]'],
];

export function redactText(value: string): string {
  return SECRET_PATTERNS.reduce((text, [pattern, replacement]) => text.replace(pattern, replacement), value);
}

export function redactDeep<T>(value: T): T {
  if (typeof value === 'string') return redactText(value) as T;
  if (Array.isArray(value)) return value.map((item) => redactDeep(item)) as T;
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value).map(([key, child]) => [
        key,
        /authorization|cookie|token|secret|password|passwd|api[-_]?key/i.test(key)
          ? '[REDACTED]'
          : redactDeep(child),
      ]),
    ) as T;
  }
  return value;
}
