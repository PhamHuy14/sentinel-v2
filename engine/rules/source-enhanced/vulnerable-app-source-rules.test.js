import { describe, expect, it } from 'vitest';
import { runVulnerableAppSourceRules } from './vulnerable-app-source-rules.js';

describe('Vulnerable app source rules', () => {
  it('detects common vulnerable source patterns from intentionally vulnerable apps', () => {
    const findings = runVulnerableAppSourceRules({
      codeFiles: [
        {
          path: 'routes/search.ts',
          content: 'sequelize.query(`SELECT * FROM Products WHERE name = ${req.query.q}`);',
        },
        {
          path: 'routes/basket.ts',
          content: 'Basket.findByPk(req.params.id); Order.update(req.body, { where: { UserId: req.body.UserId } });',
        },
        {
          path: 'routes/redirect.ts',
          content: 'if (url.includes(allowedUrl)) res.redirect(url);',
        },
        {
          path: 'server.ts',
          content: "app.use('/ftp', serveIndex('ftp'));",
        },
        {
          path: 'routes/xml.ts',
          content: 'libxml.parseXml(req.body.xml, { noent: true }); yaml.load(req.body.config);',
        },
      ],
    });

    const ids = findings.map((finding) => finding.ruleId);
    expect(ids).toContain('A03-SQLI-SRC-001');
    expect(ids).toContain('A01-IDOR-SRC-001');
    expect(ids).toContain('A01-REDIRECT-SRC-001');
    expect(ids).toContain('A05-DIRLIST-SRC-001');
    expect(ids).toContain('A03-XXE-SRC-001');
    expect(ids).toContain('A08-YAML-SRC-001');
    expect(findings.every((finding) => finding.collector === 'source')).toBe(true);
  });
});
