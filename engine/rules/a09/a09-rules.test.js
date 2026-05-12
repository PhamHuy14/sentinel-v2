import { describe, expect, it } from 'vitest';
import {
    runAlertingCheck,
    runAllA09Rules,
    runAuthEventLogging,
    runLogInjection,
    runSensitiveDataInLogs,
} from './index.js';

describe('A09 Security Logging and Monitoring Failures', () => {
  it('triggers A09-ALERT-001 when no monitoring framework is present', () => {
    const findings = runAlertingCheck({ codeFiles: [], configFiles: [] });
    expect(findings.some(f => f.ruleId === 'A09-ALERT-001')).toBe(true);
  });

  it('triggers A09-ALERT-002 for debug log level in production config', () => {
    const findings = runAlertingCheck({
      codeFiles: [],
      configFiles: [{ path: 'appsettings.Production.json', content: '"logLevel": "debug"' }],
    });
    expect(findings.some(f => f.ruleId === 'A09-ALERT-002')).toBe(true);
  });

  it('triggers A09-ALERT-003 for error suppression', () => {
    const findings = runAlertingCheck({
      codeFiles: [{ path: 'app.js', content: 'try { doWork(); } catch (e) {}' }],
      configFiles: [],
    });
    expect(findings.some(f => f.ruleId === 'A09-ALERT-003')).toBe(true);
  });

  it('triggers A09-ALERT-004 when security events logged via console.log', () => {
    const findings = runAlertingCheck({
      codeFiles: [{ path: 'auth.js', content: 'console.log("login failed")' }],
      configFiles: [],
    });
    expect(findings.some(f => f.ruleId === 'A09-ALERT-004')).toBe(true);
  });

  it('triggers auth event logging findings for login without logs', () => {
    const findings = runAuthEventLogging({
      codeFiles: [{ path: 'auth.ts', content: 'function login(user){ authenticate(user); }' }],
    });
    const ids = findings.map(f => f.ruleId);
    expect(ids).toContain('A09-LOG-LOGIN-001');
    expect(ids).toContain('A09-LOG-FAIL-001');
  });

  it('triggers log injection for user input in logs', () => {
    const findings = runLogInjection({
      codeFiles: [{ path: 'api.js', content: 'logger.info("user=" + req.query.name);' }],
      finalUrl: 'https://example.com',
      text: '',
    });
    const ids = findings.map(f => f.ruleId);
    expect(ids).toContain('A09-LOGINJ-001');
    expect(ids).toContain('A09-LOGINJ-002');
  });

  it('triggers sensitive credential logging', () => {
    const findings = runSensitiveDataInLogs({
      codeFiles: [{ path: 'auth.js', content: 'logger.info("password=" + password);' }],
    });
    expect(findings.some(f => f.ruleId === 'A09-SENSITLOG-001')).toBe(true);
  });

  it('runAllA09Rules aggregates findings', () => {
    const findings = runAllA09Rules({
      codeFiles: [{ path: 'auth.js', content: 'console.log("login failed");' }],
      configFiles: [{ path: 'appsettings.Production.json', content: '"logLevel":"debug"' }],
      text: '',
      finalUrl: 'https://example.com',
    });
    expect(findings.length).toBeGreaterThan(0);
  });
});
