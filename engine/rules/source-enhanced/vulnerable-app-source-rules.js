const { normalizeFinding } = require('../../models/finding');

const A01_REF = 'https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/';
const A03_REF = 'https://owasp.org/Top10/2025/A03_2025-Injection/';
const A05_REF = 'https://owasp.org/Top10/2025/A05_2025-Security_Misconfiguration/';
const A08_REF = 'https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/';

function sourceFiles(context) {
  return context.codeFiles || [];
}

function pushOnce(findings, seen, partial) {
  const key = `${partial.ruleId}:${partial.target}:${partial.location}`;
  if (seen.has(key)) return;
  seen.add(key);
  findings.push(normalizeFinding({ collector: 'source', ...partial }));
}

function hasOwnerCheck(content) {
  return /\b(owner|ownership|authorize|authorizeUser|canAccess|checkAccess|isOwner|userId)\b/i.test(content) &&
    /(?:req\.user|res\.locals\.user|session\.user|currentUser|principal|auth)/i.test(content);
}

function runVulnerableAppSourceRules(context) {
  const findings = [];
  const seen = new Set();

  for (const file of sourceFiles(context)) {
    const content = file?.content || '';
    const target = file?.path || 'source file';
    if (!content.trim()) continue;

    if (
      /sequelize\.query\s*\(\s*`[\s\S]{0,300}\$\{[\s\S]{0,120}(?:req\.|request\.|params\.|query\.|body\.|userInput)/i.test(content) ||
      /sequelize\.query\s*\([^)]*(?:req\.|request\.)(?:query|params|body)\.\w+/i.test(content)
    ) {
      pushOnce(findings, seen, {
        ruleId: 'A03-SQLI-SRC-001',
        owaspCategory: 'A03',
        title: 'sequelize.query dùng template string hoặc input từ request',
        severity: 'high',
        confidence: 'medium',
        target,
        location: target,
        evidence: ['Phát hiện sequelize.query nhận template literal hoặc req.query/req.params/req.body.'],
        remediation: 'Dùng bind/replacements của Sequelize hoặc query builder/ORM API thay vì nối chuỗi SQL.',
        references: [A03_REF, 'https://sequelize.org/docs/v6/core-concepts/raw-queries/'],
      });
    }

    if (/(?:find|findOne|findAll|update|destroy|deleteOne|findOneAndUpdate)\s*\(\s*\{[\s\S]{0,250}(?:req\.|request\.)(?:query|params|body)\.\w+/i.test(content)) {
      pushOnce(findings, seen, {
        ruleId: 'A03-NOSQLI-SRC-001',
        owaspCategory: 'A03',
        title: 'NoSQL query dùng object từ request trực tiếp',
        severity: 'high',
        confidence: 'medium',
        target,
        location: target,
        evidence: ['Phát hiện query object nhận req.query/req.params/req.body trực tiếp.'],
        remediation: 'Validate schema, allowlist field được phép filter, reject operator keys như $where/$ne/$gt từ client.',
        references: [A03_REF, 'https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html'],
      });
    }

    const idorSignal = /req\.params\.id|req\.body\.UserId|req\.body\.userId|req\.body\.user_id/i.test(content) &&
      /\.(?:findByPk|findOne|findAll|update|destroy|delete|remove)\s*\(/i.test(content);
    if (idorSignal && !hasOwnerCheck(content)) {
      pushOnce(findings, seen, {
        ruleId: 'A01-IDOR-SRC-001',
        owaspCategory: 'A01',
        title: 'IDOR/Broken Access Control: dùng id/UserId từ request thiếu owner check rõ ràng',
        severity: 'high',
        confidence: 'medium',
        target,
        location: target,
        evidence: ['Phát hiện req.params.id hoặc req.body.UserId được dùng cho data access nhưng không thấy owner/authorization check gần đó.'],
        remediation: 'Luôn ràng buộc truy vấn theo user hiện tại, ví dụ WHERE id = :id AND UserId = req.user.id, hoặc gọi policy/authorization middleware.',
        references: [A01_REF, 'https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html'],
      });
    }

    if (/url\.includes\s*\(\s*allowedUrl\s*\)|(?:redirectUrl|returnUrl|nextUrl|url)\.includes\s*\(\s*allowed/i.test(content)) {
      pushOnce(findings, seen, {
        ruleId: 'A01-REDIRECT-SRC-001',
        owaspCategory: 'A01',
        title: 'Open Redirect: allowlist kiểm tra bằng url.includes(...)',
        severity: 'medium',
        confidence: 'high',
        target,
        location: target,
        evidence: ['Phát hiện url.includes(allowedUrl), có thể bị bypass bằng domain nằm trong query/path.'],
        remediation: 'Parse URL bằng URL(), so sánh chính xác origin/hostname với allowlist, và chỉ cho phép http/https.',
        references: [A01_REF, 'https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html'],
      });
    }

    if (/serveIndex\s*\(/i.test(content)) {
      pushOnce(findings, seen, {
        ruleId: 'A05-DIRLIST-SRC-001',
        owaspCategory: 'A05',
        title: 'Directory Listing bật qua serveIndex(...)',
        severity: 'medium',
        confidence: 'high',
        target,
        location: target,
        evidence: ['Phát hiện Express serveIndex(...), endpoint có thể liệt kê file/thư mục.'],
        remediation: 'Tắt directory listing trong production; chỉ serve file tĩnh cần thiết và chặn truy cập thư mục nhạy cảm.',
        references: [A05_REF],
      });
    }

    if (/libxml\.parseXml\s*\([\s\S]{0,500}noent\s*:\s*true/i.test(content)) {
      pushOnce(findings, seen, {
        ruleId: 'A03-XXE-SRC-001',
        owaspCategory: 'A03',
        title: 'XXE risk: libxml.parseXml bật noent: true',
        severity: 'high',
        confidence: 'high',
        target,
        location: target,
        evidence: ['Phát hiện libxml.parseXml(..., { noent: true }), parser có thể expand entity từ XML không tin cậy.'],
        remediation: 'Tắt entity expansion/external entity, reject DOCTYPE, và parse XML bằng cấu hình an toàn.',
        references: [A03_REF, 'https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html'],
      });
    }

    if (/\byaml\.load\s*\(/i.test(content)) {
      pushOnce(findings, seen, {
        ruleId: 'A08-YAML-SRC-001',
        owaspCategory: 'A08',
        title: 'Unsafe YAML deserialization qua yaml.load(...)',
        severity: 'high',
        confidence: 'high',
        target,
        location: target,
        evidence: ['Phát hiện yaml.load(...), có thể deserialize tag/object không an toàn tùy thư viện và schema.'],
        remediation: 'Dùng safeLoad/FAILSAFE_SCHEMA/JSON_SCHEMA hoặc API safe parse, và validate schema sau khi parse.',
        references: [A08_REF, 'https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html'],
      });
    }
  }

  return findings;
}

module.exports = { runVulnerableAppSourceRules };
