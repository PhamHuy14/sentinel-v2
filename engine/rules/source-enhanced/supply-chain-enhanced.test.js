import { describe, expect, it } from 'vitest';
import {
    runCiCdSecurityGates,
    runPackageLockConsistency,
    runSensitiveDataInLogs,
    runStructuredLogging,
    runTyposquattingRisk,
} from './supply-chain-enhanced.js';

describe('Source-enhanced supply chain checks', () => {
  it('detects legacy lockfile and missing integrity', () => {
    const findings = runPackageLockConsistency({
      packageJson: '{"name":"demo"}',
      packageLockJson: JSON.stringify({
        lockfileVersion: 1,
        packages: {
          '': { name: 'demo' },
          'node_modules/foo': { version: '1.0.0' }
        },
      }),
      packageJsonPath: 'package.json',
    });
    const ids = findings.map(f => f.ruleId);
    expect(ids).toContain('A03-LOCK-001');
    expect(ids).toContain('A03-LOCK-002');
  });

  it('detects typosquatting dependency', () => {
    const findings = runTyposquattingRisk({
      packageJson: JSON.stringify({ dependencies: { lodahs: '1.0.0' } }),
      packageJsonPath: 'package.json',
    });
    expect(findings.some(f => f.ruleId === 'A03-TYPO-001')).toBe(true);
  });

  it('detects missing SAST and dependency checks in CI', () => {
    const findings = runCiCdSecurityGates({
      configFiles: [{
        path: '.github/workflows/ci.yml',
        content: 'steps:\n- uses: actions/checkout@v3\n- run: npm test'
      }],
      textFiles: [],
    });
    const ids = findings.map(f => f.ruleId);
    expect(ids).toContain('A08-CI-001');
    expect(ids).toContain('A08-CI-002');
  });

  it('detects sensitive data logging in source', () => {
    const findings = runSensitiveDataInLogs({
      codeFiles: [{ path: 'auth.js', content: 'console.log("token=" + token);' }],
    });
    expect(findings.some(f => f.ruleId === 'A09-SENSLOG-001')).toBe(true);
  });

  it('detects console-only logging', () => {
    const findings = runStructuredLogging({
      codeFiles: [{ path: 'app.js', content: 'console.log("hello");' }],
    });
    expect(findings.some(f => f.ruleId === 'A09-STRUCT-001')).toBe(true);
  });
});
