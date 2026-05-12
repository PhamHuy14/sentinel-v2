export const OWASP_2025_CATEGORIES: Record<string, string> = {
  A01: 'Broken Access Control',
  A02: 'Cryptographic Failures',
  A03: 'Injection',
  A04: 'Insecure Design',
  A05: 'Security Misconfiguration',
  A06: 'Vulnerable & Outdated Components',
  A07: 'Identification & Authentication Failures',
  A08: 'Software & Data Integrity Failures',
  A09: 'Security Logging & Monitoring Failures',
  A10: 'Server-Side Request Forgery',
};

export type ScanCoverageItem = {
  id: string;
  name: string;
  summary: string;
};

export const URL_SCAN_COVERAGE: ScanCoverageItem[] = [
  { id: 'A01', name: OWASP_2025_CATEGORIES.A01, summary: 'IDOR, forced browsing, auth bypass, privilege escalation.' },
  { id: 'A02', name: OWASP_2025_CATEGORIES.A02, summary: 'HTTPS/TLS, cookie flags, weak crypto hints, sensitive data over transport.' },
  { id: 'A03', name: OWASP_2025_CATEGORIES.A03, summary: 'XSS, SQLi, command injection, SSTI, XXE, LDAP/XPath patterns.' },
  { id: 'A04', name: OWASP_2025_CATEGORIES.A04, summary: 'Attack-surface and security-design review heuristics.' },
  { id: 'A05', name: OWASP_2025_CATEGORIES.A05, summary: 'Default pages, directory listing, GraphQL/API exposure, version disclosure.' },
  { id: 'A07', name: OWASP_2025_CATEGORIES.A07, summary: 'Account enumeration, session fixation, reset flow, MFA/OAuth/session hints.' },
  { id: 'A08', name: OWASP_2025_CATEGORIES.A08, summary: 'Deserialization and response-side integrity indicators.' },
  { id: 'A10', name: OWASP_2025_CATEGORIES.A10, summary: 'SSRF checks currently stay in the URL scanner path.' },
];

export const PROJECT_SCAN_COVERAGE: ScanCoverageItem[] = [
  { id: 'A02', name: OWASP_2025_CATEGORIES.A02, summary: 'Weak hashing/cipher/JWT/TLS patterns in source and config files.' },
  { id: 'A03', name: OWASP_2025_CATEGORIES.A03, summary: 'Injection-prone source patterns and validation/escaping heuristics.' },
  { id: 'A04', name: OWASP_2025_CATEGORIES.A04, summary: 'Missing threat model, missing abuse/rate-limit design, weak authorization-by-design.' },
  { id: 'A05', name: OWASP_2025_CATEGORIES.A05, summary: 'Misconfiguration signals in config, API, framework/default exposure patterns.' },
  { id: 'A06', name: OWASP_2025_CATEGORIES.A06, summary: 'npm/NuGet/framework version risk, lockfile and dependency hygiene.' },
  { id: 'A08', name: OWASP_2025_CATEGORIES.A08, summary: 'SRI, untrusted config/data, deserialization, CI/CD pipeline integrity.' },
  { id: 'A09', name: OWASP_2025_CATEGORIES.A09, summary: 'Sensitive data in logs and structured logging coverage.' },
];

export function normalizeOwaspCategory(category?: string): string {
  const raw = String(category || '').trim().toUpperCase();
  const match = raw.match(/^A(\d{1,2})$/);
  if (!match) return raw || 'OTHER';
  return `A${match[1].padStart(2, '0')}`;
}

export function getOwaspCategoryName(category?: string): string {
  return OWASP_2025_CATEGORIES[normalizeOwaspCategory(category)] || 'Other / Custom Rule';
}

export function formatOwaspCategory(category?: string): string {
  const normalized = normalizeOwaspCategory(category);
  return `${normalized} - ${getOwaspCategoryName(normalized)}`;
}
