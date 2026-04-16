import { describe, expect, it } from 'vitest';
import { routeQuery } from './aiRouter';

describe('aiRouter routing', () => {
  it('answers Docker security (regression: not path traversal)', () => {
    const ans = routeQuery({ question: 'Docker security là gì?' });
    expect(ans).toContain('Docker security');
    expect(ans).toContain('hardening container images');
    // Regression guard: previously `extractTopic()` could return `path_traversal` for everything.
    expect(ans).not.toContain('Attack using ../');
  });

  it('answers Path Traversal correctly', () => {
    const ans = routeQuery({ question: 'Path traversal là gì?' });
    expect(ans).toContain('../');
    expect(ans).toMatch(/access file|directory|validate path/i);
  });

  it('routes findings severity to faq_severity', () => {
    const ans = routeQuery({ question: 'Severity là gì?' });
    expect(ans.toLowerCase()).toContain('critical');
    expect(ans).toMatch(/Critical|High|Medium|Low/i);
  });

  it('routes false positive to faq_false_positive', () => {
    const ans = routeQuery({ question: 'False positive là gì?' });
    expect(ans.toLowerCase()).toContain('không');
    expect(ans.toLowerCase()).toContain('heuristic');
  });

  it('routes risk score to faq_risk_score', () => {
    const ans = routeQuery({ question: 'Risk Score là gì và được tính thế nào?' });
    expect(ans.toLowerCase()).toContain('critical +10');
    expect(ans).toMatch(/0\s*[-–]\s*100/);
  });

  it('routes 2fa/mfa to faq_2fa_mfa', () => {
    const ans = routeQuery({ question: '2FA/MFA là gì?' });
    expect(ans.toLowerCase()).toContain('2fa');
    expect(ans).toMatch(/Xác thực|Authentication/i);
  });

  it('routes collector to faq_collector', () => {
    const ans = routeQuery({ question: 'Collector trong Findings là gì?' });
    expect(ans.toLowerCase()).toContain('collector');
    expect(ans).toMatch(/config-scanner|secret-scanner|dependency-scanner|tool/i);
  });
});

