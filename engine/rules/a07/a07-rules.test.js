import { describe, it, expect } from 'vitest';
import { runAllA07Rules } from './index.js';

describe('A07 Identification and Authentication Failures', () => {

  describe('Account Enumeration', () => {
    it('should detect login enumeration via specific error messages', () => {
      const context = { text: 'wrong password', finalUrl: 'https://example.com/login', authHints: { hasLoginHint: true } };
      const findings = runAllA07Rules(context);
      expect(findings.some(f => f.ruleId === 'A07-ENUM-001')).toBe(true);
    });

    it('should detect HTTP 404 for account enumeration', () => {
      const context = { status: 404, finalUrl: 'https://example.com/login', authHints: { hasLoginHint: true } };
      const findings = runAllA07Rules(context);
      expect(findings.some(f => f.ruleId === 'A07-ENUM-003')).toBe(true);
    });
  });

  describe('Auth Enhanced', () => {
    it('should detect tokens in URLs', () => {
      const context = { finalUrl: 'https://example.com/dashboard?access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz' };
      const findings = runAllA07Rules(context);
      expect(findings.some(f => f.ruleId === 'A07-TOKENURL-001')).toBe(true);
    });

    it('should detect OAuth implicit flow', () => {
      const context = { finalUrl: 'https://example.com/oauth/authorize?response_type=token&client_id=123' };
      const findings = runAllA07Rules(context);
      expect(findings.some(f => f.ruleId === 'A07-OAUTH-001')).toBe(true);
    });

    it('should detect weak session entropy', () => {
      const context = { setCookies: ['JSESSIONID=12345;'] };
      const findings = runAllA07Rules(context);
      expect(findings.some(f => f.ruleId === 'A07-SESSION-ENTROPY-001')).toBe(true);
    });
  });

  describe('Reset Flow', () => {
    it('should detect missing throttling in reset flow', () => {
      const context = { authHints: { hasForgotPasswordHint: true }, text: 'forgot password' };
      const findings = runAllA07Rules(context);
      expect(findings.some(f => f.ruleId === 'A07-RESET-001')).toBe(true);
    });

    it('should detect reset token in URL', () => {
      const context = { authHints: { hasForgotPasswordHint: true }, finalUrl: 'https://example.com/reset?token=abcdef123456' };
      const findings = runAllA07Rules(context);
      expect(findings.some(f => f.ruleId === 'A07-RESET-002')).toBe(true);
    });
  });

  describe('Session Fixation & Management', () => {
    it('should detect missing Secure flag when SameSite=None', () => {
      const context = { setCookies: ['session_id=123; SameSite=None'] };
      const findings = runAllA07Rules(context);
      expect(findings.some(f => f.ruleId === 'A07-SESSION-004')).toBe(true);
    });

    it('should detect session ID in URL', () => {
      const context = { finalUrl: 'https://example.com/app?JSESSIONID=ABCDEF1234567890ABCDEF' };
      const findings = runAllA07Rules(context);
      expect(findings.some(f => f.ruleId === 'A07-SESSFIXATION-001')).toBe(true);
    });
  });
});
