import { describe, it, expect } from 'vitest';
import { runAllA08Rules } from './index.js';

describe('A08 Software and Data Integrity Failures', () => {

  describe('Deserialization (Blackbox)', () => {
    it('should detect Java deserialization errors', () => {
      const context = { text: 'java.io.InvalidClassException: local class incompatible', finalUrl: 'https://example.com/api' };
      const findings = runAllA08Rules(context);
      expect(findings.some(f => f.ruleId === 'A08-DESER-001')).toBe(true);
    });

    it('should detect serialized magic bytes in response', () => {
      const context = { text: 'Payload: rO0ABXNyAAp', finalUrl: 'https://example.com/api' };
      const findings = runAllA08Rules(context);
      expect(findings.some(f => f.ruleId === 'A08-DESER-002')).toBe(true);
    });
  });

  describe('SRI / Integrity Controls (Source)', () => {
    it('should detect CDN script without SRI', () => {
      const context = {
        textFiles: [{
          path: 'index.html',
          content: '<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>'
        }]
      };
      const findings = runAllA08Rules(context);
      expect(findings.some(f => f.ruleId === 'A08-INTEGRITY-001')).toBe(true);
    });

    it('should detect missing crossorigin attribute with integrity', () => {
      const context = {
        textFiles: [{
          path: 'index.html',
          content: '<script src="https://example.com/script.js" integrity="sha384-xyz"></script>'
        }]
      };
      const findings = runAllA08Rules(context);
      expect(findings.some(f => f.ruleId === 'A08-INTEGRITY-003')).toBe(true);
    });
  });

  describe('Untrusted Config Data / Unsafe Execution (Source)', () => {
    it('should detect unsafe YAML load in Python', () => {
      const context = {
        codeFiles: [{
          path: 'app.py',
          content: 'import yaml\nyaml.load(user_input)'
        }]
      };
      const findings = runAllA08Rules(context);
      expect(findings.some(f => f.ruleId === 'A08-CONFIG-002')).toBe(true);
    });

    it('should detect unsafe eval in JavaScript', () => {
      const context = {
        codeFiles: [{
          path: 'server.js',
          content: 'eval(req.body.code);'
        }]
      };
      const findings = runAllA08Rules(context);
      expect(findings.some(f => f.ruleId === 'A08-CONFIG-001')).toBe(true);
    });
  });

  describe('CI/CD Pipeline Security (Source)', () => {
    it('should detect unpinned GitHub Actions', () => {
      const context = {
        ciFiles: [{
          path: '.github/workflows/deploy.yml',
          content: 'steps:\n- uses: actions/checkout@main'
        }]
      };
      const findings = runAllA08Rules(context);
      expect(findings.some(f => f.ruleId === 'A08-CI-004')).toBe(true);
    });

    it('should detect hardcoded secrets in CI config', () => {
      const context = {
        ciFiles: [{
          path: '.gitlab-ci.yml',
          content: 'variables:\n  DB_PASSWORD: "SuperSecretPassword123!"'
        }]
      };
      const findings = runAllA08Rules(context);
      expect(findings.some(f => f.ruleId === 'A08-CI-005')).toBe(true);
    });
  });

});
