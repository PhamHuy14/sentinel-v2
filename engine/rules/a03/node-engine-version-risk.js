const { normalizeFinding } = require('../../models/finding');

// Node.js EOL schedule — https://nodejs.org/en/about/previous-releases
// Chỉ check major version, đơn giản hóa thay vì full semver parse
const EOL_NODE_MAJORS = [
  { major: 0,  eolDate: '2016-12-31' },
  { major: 4,  eolDate: '2018-04-30' },
  { major: 6,  eolDate: '2019-04-30' },
  { major: 8,  eolDate: '2019-12-31' },
  { major: 10, eolDate: '2021-04-30' },
  { major: 12, eolDate: '2022-04-30' },
  { major: 14, eolDate: '2023-04-30' },
  { major: 16, eolDate: '2023-09-11' },
  { major: 17, eolDate: '2022-06-01' },
  { major: 19, eolDate: '2023-06-01' },
  { major: 21, eolDate: '2024-06-01' },
];

/**
 * Parse minimum major version từ semver range đơn giản.
 * Hỗ trợ: ">=14", "^16", "~18", "16", "16.x", ">=14.0.0 <22", "14 || 16 || 18"
 * Trả về số major nhỏ nhất tìm được, hoặc null nếu không parse được.
 */
function parseMinMajor(range) {
  if (!range) return null;
  // Tách các alternatives: "14 || 16 || 18" → lấy tất cả major
  const parts = String(range).split('||').map(s => s.trim());
  const majors = [];
  for (const part of parts) {
    // Loại bỏ operators: >=, <=, ~, ^, >, <, =, space
    const clean = part.replace(/[>=<~^]/g, '').trim();
    // Lấy phần đầu tiên (có thể là "16.0.0", "16.x", "16")
    const tokens = clean.split(/\s+/);
    for (const token of tokens) {
      const m = token.match(/^(\d+)/);
      if (m) {
        majors.push(parseInt(m[1], 10));
        break;
      }
    }
  }
  if (majors.length === 0) return null;
  return Math.min(...majors);
}

function runNodeEngineVersionRisk(context) {
  const findings = [];
  try {
    const text = context.packageJson || '';
    if (!text) return findings;

    const data = JSON.parse(text);
    const engines = data.engines || null;

    // ── A03-NODE-002: Không có engines field ────────────────────────────────
    if (!engines || !engines.node) {
      findings.push(normalizeFinding({
        ruleId: 'A03-NODE-002',
        owaspCategory: 'A03',
        title: 'package.json không khai báo engines.node constraint',
        severity: 'low',
        confidence: 'high',
        target: context.packageJsonPath,
        location: 'package.json → engines',
        evidence: ['Không có field "engines.node" trong package.json'],
        remediation:
          'Thiếu engine constraint cho phép project chạy trên bất kỳ Node version nào, ' +
          'bao gồm các version đã EOL và không nhận security patch. ' +
          'Thêm "engines": { "node": ">=20.0.0" } và enforce bằng .nvmrc hoặc volta.',
        references: ['https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/'],
        collector: 'source'
      }));
      return findings;
    }

    // ── A03-NODE-001: engines.node yêu cầu version đã EOL ───────────────────
    const nodeRange = engines.node;
    const minMajor = parseMinMajor(nodeRange);

    if (minMajor !== null && minMajor < 16) {
      const eolInfo = EOL_NODE_MAJORS.find(e => e.major === minMajor);
      findings.push(normalizeFinding({
        ruleId: 'A03-NODE-001',
        owaspCategory: 'A03',
        title: `engines.node cho phép Node.js v${minMajor} đã đạt End-of-Life (${eolInfo?.eolDate || 'EOL'})`,
        severity: minMajor < 12 ? 'high' : 'medium',
        confidence: 'medium',
        target: context.packageJsonPath,
        location: 'package.json → engines.node',
        evidence: [`engines.node: "${nodeRange}" — minimum major version: ${minMajor}`],
        remediation:
          `Node.js v${minMajor} EOL từ ${eolInfo?.eolDate || 'trước đây'}, không nhận security patch. ` +
          'Cập nhật constraint lên ">=20.0.0" (Node 20 LTS) hoặc ">=22.0.0". ' +
          'Update Dockerfile, CI pipeline và .nvmrc/volta config đồng thời.',
        references: [
          'https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/',
          'https://nodejs.org/en/about/previous-releases',
          'https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/02-Test_Application_Platform_Configuration'
        ],
        collector: 'source'
      }));
    }
  } catch {
    return findings;
  }

  return findings;
}

module.exports = { runNodeEngineVersionRisk };
