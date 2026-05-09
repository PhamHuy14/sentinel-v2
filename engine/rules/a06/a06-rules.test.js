/* eslint-env jest */
/* eslint-disable @typescript-eslint/no-var-requires */

const { runDefaultPageCheck } = require('./default-page-check');
const { runDirectoryListingCheck } = require('./directory-listing-check');
const { runGraphqlIntrospectionCheck, runApiMisconfigCheck } = require('./api-misconfig');
const { runFrameworkDisclosureCheck } = require('./framework-version-disclosure');

describe('A06 Security Misconfiguration Rules', () => {
  it('should detect Default Page', () => {
    const context = { text: '<h1>Welcome to nginx!</h1>', finalUrl: 'http://test' };
    const findings = runDefaultPageCheck(context);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].ruleId).toBe('A06-DEFAULT-001');
  });

  it('should detect Directory Listing', () => {
    const context = { text: '<h1>Index of /images</h1>', status: 200, finalUrl: 'http://test' };
    const findings = runDirectoryListingCheck(context);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].ruleId).toBe('A06-DIRLIST-001');
  });

  it('should detect Sensitive File in Directory Listing', () => {
    const context = { text: '<h1>Index of /</h1> <a href=".env">.env</a>', status: 200, finalUrl: 'http://test' };
    const findings = runDirectoryListingCheck(context);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].severity).toBe('critical');
  });

  it('should detect GraphQL Introspection', () => {
    const context = { text: '{"__schema": { "queryType": {} } }', contentType: 'application/json', finalUrl: 'http://test' };
    const findings = runGraphqlIntrospectionCheck(context);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].ruleId).toBe('A06-GRAPHQL-001');
  });

  it('should detect API Misconfig (Swagger leak)', () => {
    const context = { text: '{"swagger": "2.0", "info": {}}', finalUrl: 'http://test' };
    const findings = runApiMisconfigCheck(context);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].ruleId).toBe('A06-API-001');
  });

  it('should detect Framework Version Disclosure', () => {
    const htmlContext = { text: '<meta name="generator" content="WordPress 5.7">', contentType: 'text/html', finalUrl: 'http://test' };
    const findings = runFrameworkDisclosureCheck(htmlContext);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].ruleId).toBe('A06-VERSION-001');
  });
});
