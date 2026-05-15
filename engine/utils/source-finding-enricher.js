const {
  buildSourceRemediationPlan,
  evidenceWithLocation,
  locatePattern,
} = require('./source-locator');

function hasLine(location) {
  return /:\d+(?::\d+)?$/.test(String(location || '')) || /:\d+-\d+$/.test(String(location || ''));
}

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function fileForFinding(finding, filesByPath) {
  const target = String(finding.target || '');
  const location = String(finding.location || '').replace(/:\d+(?::\d+)?$/, '');
  return filesByPath.get(target) || filesByPath.get(location) || null;
}

function evidencePattern(finding) {
  const evidence = (finding.evidence || [])
    .map(String)
    .find((item) =>
      /(?:console\.|logger\.|req\.|request\.|fetch\(|axios|sequelize\.query|yaml\.load|parseXml|exec\(|spawn\(|set-cookie|createHash|createCipher|cors\()/i.test(item),
    );

  if (!evidence) return null;
  const compact = evidence
    .replace(/^.*?:\s*/, '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 120);
  return compact.length >= 8 ? new RegExp(escapeRegExp(compact), 'i') : null;
}

function catalogPatterns(finding) {
  const rule = String(finding.ruleId || '');
  const title = String(finding.title || '');
  const haystack = `${rule} ${title}`;
  const patterns = [];

  if (/SQLI|INJECTION/i.test(haystack)) {
    patterns.push({
      re: /(?:sequelize\.query|\.query\s*\(|SELECT\s+[\s\S]{0,160}(?:req\.|request\.|params|query|body)|\$\{[\s\S]{0,120}(?:req\.|request\.|params|query|body))/i,
      focusPatterns: [/sequelize\.query|\.query\s*\(|SELECT/i, /(?:req\.|request\.|params|query|body|\$\{)/i],
    });
  }
  if (/NOSQL|MONGO/i.test(haystack)) {
    patterns.push({
      re: /(?:find|findOne|findAll|update|destroy|deleteOne|findOneAndUpdate)\s*\([\s\S]{0,260}(?:req\.|request\.)(?:query|params|body)/i,
      focusPatterns: [/(?:find|findOne|findAll|update|destroy|deleteOne|findOneAndUpdate)\s*\(/i, /(?:req\.|request\.)/i],
    });
  }
  if (/IDOR|ACCESS|AUTHZ|AUTHORIZATION/i.test(haystack)) {
    patterns.push({
      re: /\.(?:findByPk|findOne|findAll|destroy|update|delete|remove)\s*\(/i,
      focusPatterns: [/findByPk|findOne|findAll|destroy|update|delete|remove/i],
    });
    patterns.push({
      re: /(?:req\.params\.id|req\.body\.UserId|req\.body\.userId|req\.body\.user_id|findByPk|findOne|findAll|destroy|update)/i,
      focusPatterns: [/req\.params\.id|req\.body/i, /findByPk|findOne|findAll|destroy|update/i],
    });
  }
  if (/SSRF|REDIRECT/i.test(haystack)) {
    patterns.push({
      re: /(?:fetch|axios|https?\.get|https?\.request|request\s*\(|got\s*\(|res\.redirect|sendRedirect|Location:)[\s\S]{0,260}(?:req\.|request\.|params|query|body|\$_(?:GET|POST|REQUEST))/i,
      focusPatterns: [/fetch|axios|https?\.get|request|got|redirect|Location:/i, /(?:req\.|request\.|\$_(?:GET|POST|REQUEST))/i],
    });
  }
  if (/LOG|SENSLOG|STRUCT/i.test(haystack)) {
    patterns.push({
      re: /(?:console\.(?:log|error|warn)|logger\.(?:info|debug|warn|error)|log\.)[\s\S]{0,220}(?:password|passwd|token|secret|authorization|cookie|req\.body|req\.headers)/i,
      focusPatterns: [/console\.|logger\.|log\./i, /password|token|secret|authorization|cookie|req\.body|req\.headers/i],
    });
    patterns.push({ re: /console\.(?:log|error|warn)\s*\(/i, focusPatterns: [/console\./i] });
  }
  if (/CMD|COMMAND|RCE/i.test(haystack)) {
    patterns.push({
      re: /(?:exec|execFile|spawn|system|popen|Runtime\.getRuntime\(\)\.exec)\s*\([\s\S]{0,220}(?:req\.|request\.|params|query|body|\$_(?:GET|POST|REQUEST))/i,
      focusPatterns: [/exec|spawn|system|popen/i, /(?:req\.|request\.|\$_(?:GET|POST|REQUEST))/i],
    });
  }
  if (/CRYPTO|HASH|CIPHER|JWT/i.test(haystack)) {
    patterns.push({
      re: /(?:createHash\s*\(\s*['"](?:md5|sha1)|createCipher|DES|3DES|RC4|alg\s*[:=]\s*['"]none)/i,
      focusPatterns: [/md5|sha1|createCipher|DES|3DES|RC4|alg/i],
    });
  }
  if (/YAML|DESER|XXE|XML/i.test(haystack)) {
    patterns.push({
      re: /(?:yaml\.load|YAML\.load|parseXml|noent\s*:\s*true|deserialize|unserialize|pickle\.loads)/i,
      focusPatterns: [/yaml\.load|parseXml|noent|deserialize|unserialize|pickle/i],
    });
  }

  const fromEvidence = evidencePattern(finding);
  if (fromEvidence) patterns.unshift({ re: fromEvidence, focusPatterns: [fromEvidence] });
  return patterns;
}

function enrichSourceFindings(findings, codeFiles) {
  const filesByPath = new Map((codeFiles || []).map((file) => [file.path, file]));

  return (findings || []).map((finding) => {
    if (finding.collector !== 'source' || hasLine(finding.location)) return finding;
    const file = fileForFinding(finding, filesByPath);
    if (!file?.content) return finding;

    const patterns = catalogPatterns(finding);
    if (!patterns.length) return finding;

    const locator = locatePattern(file.content, patterns);
    if (!locator) return finding;

    const location = `${file.path}:${locator.lineStart}`;
    const remediation = finding.remediation || 'Xác minh evidence và áp dụng biện pháp khắc phục phù hợp.';

    return {
      ...finding,
      target: finding.target || file.path,
      location,
      evidence: evidenceWithLocation(finding.evidence, locator),
      remediationPlan: finding.remediationPlan || buildSourceRemediationPlan({
        filePath: file.path,
        locator,
        summary: remediation,
        suggestedTo: remediation,
      }),
    };
  });
}

module.exports = { enrichSourceFindings };
