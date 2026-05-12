import { describe, expect, it } from 'vitest';
import { runGenericProjectChecks } from './generic-project-checks.js';

describe('Generic project checks', () => {
  it('triggers input validation, headers, and scale heuristics', () => {
    const findings = runGenericProjectChecks({
      codeFiles: [{ path: 'app.js', content: 'function app() { return true; }' }],
      configFiles: [{ path: 'config.yml', content: 'port: 3000' }],
      files: Array.from({ length: 60 }, (_, i) => ({ path: `file-${i}.txt` })),
    });
    const ids = findings.map(f => f.ruleId);
    expect(ids).toContain('GEN-INPUT-001');
    expect(ids).toContain('GEN-HEADERS-001');
    expect(ids).toContain('GEN-SCALE-001');
  });
});
