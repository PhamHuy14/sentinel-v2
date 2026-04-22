const { normalizeFinding } = require('../../models/finding');

function getHeader(headers, name) {
  if (!headers) return '';
  if (typeof headers.get === 'function') {
    return headers.get(name) || '';
  }
  return headers[name] || headers[name.toLowerCase()] || '';
}

/**
 * A02-SVR: Phát hiện Server header lộ thông tin phiên bản/technology stack.
 * Theo OWASP OTG-INFO-002 (Fingerprint Web Server).
 *
 * @param {object} context
 * @param {Headers|object} context.headers
 * @param {string} context.finalUrl
 * @param {boolean} [context.isLocalhost]
 * @returns {Array} findings
 */
function runServerHeaderExposure(context) {
  const findings = [];
  const headers = context.headers || new Headers();

  const serverHeader = getHeader(headers, 'server');
  if (serverHeader) {
    const hasVersion = /[\d]+\.[\d]+/.test(serverHeader);
    findings.push(normalizeFinding({
      ruleId: hasVersion ? 'A02-SVR-001' : 'A02-SVR-002',
      owaspCategory: 'A02',
      title: hasVersion
        ? 'Server header lộ phiên bản phần mềm cụ thể'
        : 'Server header lộ loại phần mềm',
      severity: hasVersion ? 'medium' : 'low',
      confidence: 'high',
      target: context.finalUrl,
      location: 'response headers → Server',
      evidence: [`Server: ${serverHeader}`],
      remediation:
        'Cấu hình web server ẩn hoặc tối thiểu hóa Server header.\n' +
        '• Apache: ServerTokens Prod\n' +
        '• nginx: server_tokens off\n' +
        '• IIS: removeServerHeader="true" trong applicationHost.config',
      references: [
        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server',
        'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html',
      ],
      collector: 'blackbox',
    }));
  }

  const xPoweredBy = getHeader(headers, 'x-powered-by');
  if (xPoweredBy) {
    findings.push(normalizeFinding({
      ruleId: 'A02-SVR-003',
      owaspCategory: 'A02',
      title: 'X-Powered-By header lộ technology stack',
      severity: 'medium',
      confidence: 'high',
      target: context.finalUrl,
      location: 'response headers → X-Powered-By',
      evidence: [`X-Powered-By: ${xPoweredBy}`],
      remediation:
        'Xóa header X-Powered-By:\n' +
        '• Express.js: app.disable("x-powered-by")\n' +
        '• PHP: expose_php = Off trong php.ini\n' +
        '• IIS: xPoweredBy="false"',
      references: [
        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server',
      ],
      collector: 'blackbox',
    }));
  }

  const techHeaders = [
    'x-generator',
    'x-aspnet-version',
    'x-aspnetmvc-version',
    'x-drupal-cache',
    'x-wordpress',
  ];

  for (const hName of techHeaders) {
    const val = getHeader(headers, hName);
    if (val) {
      findings.push(normalizeFinding({
        ruleId: 'A02-SVR-004',
        owaspCategory: 'A02',
        title: `Header "${hName}" lộ thông tin framework/CMS`,
        severity: 'medium',
        confidence: 'high',
        target: context.finalUrl,
        location: `response headers → ${hName}`,
        evidence: [`${hName}: ${val}`],
        remediation: `Xóa header ${hName} trong cấu hình server hoặc middleware.`,
        references: [
          'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework',
        ],
        collector: 'blackbox',
      }));
    }
  }

  return findings;
}

module.exports = { runServerHeaderExposure };
