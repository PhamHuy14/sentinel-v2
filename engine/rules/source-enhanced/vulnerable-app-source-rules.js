const { normalizeFinding } = require('../../models/finding');
const {
  buildSourceRemediationPlan,
  evidenceWithLocation,
  locatePattern,
} = require('../../utils/source-locator');

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

function sourcePartial({ target, locator, evidence, remediation, suggestedTo, ...partial }) {
  return {
    ...partial,
    target,
    location: locator ? `${target}:${locator.lineStart}` : target,
    evidence: evidenceWithLocation(evidence, locator),
    remediation,
    remediationPlan: buildSourceRemediationPlan({
      filePath: target,
      locator,
      summary: remediation,
      suggestedTo,
    }),
  };
}

function runVulnerableAppSourceRules(context) {
  const findings = [];
  const seen = new Set();

  for (const file of sourceFiles(context)) {
    const content = file?.content || '';
    const target = file?.path || 'source file';
    if (!content.trim()) continue;

    const sqliLocator = locatePattern(content, [
      {
        re: /sequelize\.query\s*\(\s*`[\s\S]{0,300}\$\{[\s\S]{0,120}(?:req\.|request\.|params\.|query\.|body\.|userInput)/i,
        focusPatterns: [/sequelize\.query/i, /\$\{/],
      },
      {
        re: /sequelize\.query\s*\([^)]*(?:req\.|request\.)(?:query|params|body)\.\w+/i,
        focusPatterns: [/sequelize\.query/i, /(?:req\.|request\.)(?:query|params|body)/i],
      },
    ]);
    if (sqliLocator) {
      const remediation = 'Dùng bind/replacements của Sequelize hoặc query builder/ORM API thay vì nối chuỗi SQL.';
      pushOnce(findings, seen, sourcePartial({
        ruleId: 'A03-SQLI-SRC-001',
        owaspCategory: 'A03',
        title: 'sequelize.query dùng template string hoặc input từ request',
        severity: 'high',
        confidence: 'medium',
        target,
        locator: sqliLocator,
        evidence: ['Phát hiện sequelize.query nhận template literal hoặc req.query/req.params/req.body.'],
        remediation,
        suggestedTo:
          'Dùng parameter binding, ví dụ: sequelize.query(sql, { replacements: { id: req.params.id }, type: QueryTypes.SELECT }).',
        references: [A03_REF, 'https://sequelize.org/docs/v6/core-concepts/raw-queries/'],
      }));
    }

    const nosqliLocator = locatePattern(
      content,
      {
        re: /(?:find|findOne|findAll|update|destroy|deleteOne|findOneAndUpdate)\s*\(\s*\{[\s\S]{0,250}(?:req\.|request\.)(?:query|params|body)\.\w+/i,
        focusPatterns: [/(?:find|findOne|findAll|update|destroy|deleteOne|findOneAndUpdate)\s*\(/i, /(?:req\.|request\.)(?:query|params|body)/i],
      },
    );
    if (nosqliLocator) {
      const remediation = 'Validate schema, allowlist field được phép filter, reject operator keys như $where/$ne/$gt từ client.';
      pushOnce(findings, seen, sourcePartial({
        ruleId: 'A03-NOSQLI-SRC-001',
        owaspCategory: 'A03',
        title: 'NoSQL query dùng object từ request trực tiếp',
        severity: 'high',
        confidence: 'medium',
        target,
        locator: nosqliLocator,
        evidence: ['Phát hiện query object nhận req.query/req.params/req.body trực tiếp.'],
        remediation,
        suggestedTo: 'Tạo object filter từ allowlist field hợp lệ thay vì truyền trực tiếp req.query/req.body vào query.',
        references: [A03_REF, 'https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html'],
      }));
    }

    const idorSignal = /req\.params\.id|req\.body\.UserId|req\.body\.userId|req\.body\.user_id/i.test(content) &&
      /\.(?:findByPk|findOne|findAll|update|destroy|delete|remove)\s*\(/i.test(content);
    if (idorSignal && !hasOwnerCheck(content)) {
      const idorLocator = locatePattern(content, [
        {
          re: /\.(?:findByPk|findOne|findAll|update|destroy|delete|remove)\s*\([^)]*(?:req\.params\.id|req\.body\.UserId|req\.body\.userId|req\.body\.user_id)/i,
          focusPatterns: [/\.(?:findByPk|findOne|findAll|update|destroy|delete|remove)\s*\(/i, /req\.(?:params|body)/i],
        },
        {
          re: /\.(?:findByPk|findOne|findAll|update|destroy|delete|remove)\s*\(/i,
          focusPatterns: [/\.(?:findByPk|findOne|findAll|update|destroy|delete|remove)\s*\(/i],
        },
        {
          re: /req\.params\.id|req\.body\.UserId|req\.body\.userId|req\.body\.user_id/i,
          focusPatterns: [/req\.params\.id|req\.body\.UserId|req\.body\.userId|req\.body\.user_id/i],
        },
      ]);
      const remediation =
        'Luôn ràng buộc truy vấn theo user hiện tại, ví dụ WHERE id = :id AND UserId = req.user.id, hoặc gọi policy/authorization middleware.';
      pushOnce(findings, seen, sourcePartial({
        ruleId: 'A01-IDOR-SRC-001',
        owaspCategory: 'A01',
        title: 'IDOR/Broken Access Control: dùng id/UserId từ request thiếu owner check rõ ràng',
        severity: 'high',
        confidence: 'medium',
        target,
        locator: idorLocator,
        evidence: ['Phát hiện req.params.id hoặc req.body.UserId được dùng cho data access nhưng không thấy owner/authorization check gần đó.'],
        remediation,
        suggestedTo: 'Thêm điều kiện owner/tenant vào truy vấn hoặc gọi middleware/policy authorization trước khi truy cập dữ liệu.',
        references: [A01_REF, 'https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html'],
      }));
    }

    const redirectLocator = locatePattern(
      content,
      {
        re: /url\.includes\s*\(\s*allowedUrl\s*\)|(?:redirectUrl|returnUrl|nextUrl|url)\.includes\s*\(\s*allowed/i,
        focusPatterns: [/\.includes\s*\(/i, /redirectUrl|returnUrl|nextUrl|url/i],
      },
    );
    if (redirectLocator) {
      const remediation = 'Parse URL bằng URL(), so sánh chính xác origin/hostname với allowlist, và chỉ cho phép http/https.';
      pushOnce(findings, seen, sourcePartial({
        ruleId: 'A01-REDIRECT-SRC-001',
        owaspCategory: 'A01',
        title: 'Open Redirect: allowlist kiểm tra bằng url.includes(...)',
        severity: 'medium',
        confidence: 'high',
        target,
        locator: redirectLocator,
        evidence: ['Phát hiện url.includes(allowedUrl), có thể bị bypass bằng domain nằm trong query/path.'],
        remediation,
        suggestedTo:
          'Parse bằng new URL(), chỉ chấp nhận origin/hostname nằm trong allowlist chính xác, ưu tiên relative path nếu có thể.',
        references: [A01_REF, 'https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html'],
      }));
    }

    const dirListLocator = locatePattern(content, /serveIndex\s*\(/i);
    if (dirListLocator) {
      const remediation = 'Tắt directory listing trong production; chỉ serve file tĩnh cần thiết và chặn truy cập thư mục nhạy cảm.';
      pushOnce(findings, seen, sourcePartial({
        ruleId: 'A05-DIRLIST-SRC-001',
        owaspCategory: 'A05',
        title: 'Directory Listing bật qua serveIndex(...)',
        severity: 'medium',
        confidence: 'high',
        target,
        locator: dirListLocator,
        evidence: ['Phát hiện Express serveIndex(...), endpoint có thể liệt kê file/thư mục.'],
        remediation,
        suggestedTo: 'Gỡ middleware serveIndex(...) ở production hoặc bảo vệ route bằng auth/allowlist chặt chẽ.',
        references: [A05_REF],
      }));
    }

    const xxeLocator = locatePattern(content, /libxml\.parseXml\s*\([\s\S]{0,500}noent\s*:\s*true/i);
    if (xxeLocator) {
      const remediation = 'Tắt entity expansion/external entity, reject DOCTYPE, và parse XML bằng cấu hình an toàn.';
      pushOnce(findings, seen, sourcePartial({
        ruleId: 'A03-XXE-SRC-001',
        owaspCategory: 'A03',
        title: 'XXE risk: libxml.parseXml bật noent: true',
        severity: 'high',
        confidence: 'high',
        target,
        locator: xxeLocator,
        evidence: ['Phát hiện libxml.parseXml(..., { noent: true }), parser có thể expand entity từ XML không tin cậy.'],
        remediation,
        suggestedTo: 'Tắt noent/entity expansion, reject DOCTYPE và dùng cấu hình parser an toàn cho XML không tin cậy.',
        references: [A03_REF, 'https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html'],
      }));
    }

    const yamlLocator = locatePattern(content, /\byaml\.load\s*\(/i);
    if (yamlLocator) {
      const remediation = 'Dùng safeLoad/FAILSAFE_SCHEMA/JSON_SCHEMA hoặc API safe parse, và validate schema sau khi parse.';
      pushOnce(findings, seen, sourcePartial({
        ruleId: 'A08-YAML-SRC-001',
        owaspCategory: 'A08',
        title: 'Unsafe YAML deserialization qua yaml.load(...)',
        severity: 'high',
        confidence: 'high',
        target,
        locator: yamlLocator,
        evidence: ['Phát hiện yaml.load(...), có thể deserialize tag/object không an toàn tùy thư viện và schema.'],
        remediation,
        suggestedTo: 'Đổi sang safeLoad/load với FAILSAFE_SCHEMA/JSON_SCHEMA hoặc API safe parse phù hợp thư viện đang dùng.',
        references: [A08_REF, 'https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html'],
      }));
    }
  }

  return findings;
}

module.exports = { runVulnerableAppSourceRules };
