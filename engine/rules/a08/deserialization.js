const { normalizeFinding } = require('../../models/finding');

/**
 * Phát hiện Insecure Deserialization trong source code
 * Tham chiếu: CWE-502, OWASP A08, WSTG-INPV-11
 *
 * Rule này focus vào BLACKBOX indicators (response-side),
 * bổ sung cho untrusted-config-data.js (source-side).
 * Phát hiện dấu hiệu deserialization error leak trong HTTP response.
 */

// Dấu hiệu deserialization error bị lộ trong response
const DESER_ERROR_PATTERNS = [
  // Java
  { re: /java\.io\.InvalidClassException|serialVersionUID/i,
    label: 'Java serialization error (InvalidClassException / serialVersionUID mismatch)', lang: 'Java' },
  { re: /java\.io\.StreamCorruptedException|java\.io\.NotSerializableException/i,
    label: 'Java StreamCorruptedException — serialized object bị corrupt hoặc tampered', lang: 'Java' },
  { re: /org\.apache\.commons\.collections|ysoserial|gadget chain/i,
    label: 'Java deserialization gadget chain reference in response', lang: 'Java' },
  // Python pickle
  { re: /pickle\.UnpicklingError|_pickle\.(Un)?PicklingError|EOFError.*pickle/i,
    label: 'Python pickle.UnpicklingError — deserialization error leaked', lang: 'Python' },
  // PHP
  { re: /unserialize\(\):\s*Error|__PHP_Incomplete_Class/i,
    label: 'PHP unserialize() error — deserialization error leaked', lang: 'PHP' },
  // .NET
  { re: /SerializationException|BinaryFormatter|DataContractSerializer.*error/i,
    label: '.NET SerializationException — deserialization error leaked', lang: '.NET' },
  // Ruby Marshal
  { re: /Marshal\.load|TypeError.*marshal/i,
    label: 'Ruby Marshal.load error — unsafe deserialization', lang: 'Ruby' },
  // Node.js
  { re: /node-serialize|serialize-javascript.*eval/i,
    label: 'Node.js node-serialize IIFE exploit reference', lang: 'Node.js' },
];

// Serialized object magic bytes bị lộ trong response body (base64 hint)
const SERIALIZED_PAYLOAD_PATTERNS = [
  // Java serialized object magic bytes: AC ED 00 05 → base64 rO0AB
  { re: /rO0AB[A-Za-z0-9+/]{4,}/,
    label: 'Java serialized object (magic bytes rO0AB) trong response — possible deserialization endpoint' },
  // PHP serialized: O:4:"User":...
  { re: /O:\d+:"[A-Za-z_\\][\w\\]*":\d+:\{/,
    label: 'PHP serialized object string trong response' },
  // Python pickle base64 hint
  { re: /gASV[A-Za-z0-9+/]{8,}/,
    label: 'Python pickle protocol 5 base64-encoded data in response' },
];

function runDeserializationHeuristic(context) {
  const text = context.text || '';
  const findings = [];

  // Check deserialization errors trong response
  const errorMatches = DESER_ERROR_PATTERNS.filter(({ re }) => re.test(text));
  if (errorMatches.length > 0) {
    findings.push(normalizeFinding({
      ruleId: 'A08-DESER-001',
      owaspCategory: 'A08',
      title: 'Lỗi deserialization bị lộ trong HTTP response',
      severity: 'high',
      confidence: 'high',
      target: context.finalUrl,
      location: 'response body',
      evidence: errorMatches.map(m => `[${m.lang}] ${m.label}`),
      remediation:
        'Ẩn deserialization error khỏi response. ' +
        'Không deserialize dữ liệu từ client mà không xác thực. ' +
        'Java: dùng ObjectInputFilter whitelist. .NET: thay BinaryFormatter bằng System.Text.Json. ' +
        'Python: thay pickle bằng json. PHP: thay unserialize bằng json_decode.',
      references: [
        'https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/',
        'https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html',
        'https://cwe.mitre.org/data/definitions/502.html',
      ],
      collector: 'blackbox',
    }));
  }

  // Check serialized payload trong response (magic bytes)
  const payloadMatches = SERIALIZED_PAYLOAD_PATTERNS.filter(({ re }) => re.test(text));
  if (payloadMatches.length > 0) {
    findings.push(normalizeFinding({
      ruleId: 'A08-DESER-002',
      owaspCategory: 'A08',
      title: 'Serialized object data phát hiện trong response — endpoint dùng deserialization',
      severity: 'medium',
      confidence: 'medium',
      target: context.finalUrl,
      location: 'response body',
      evidence: payloadMatches.map(m => m.label),
      remediation:
        'Xác nhận endpoint này có nhận serialized object từ client không. ' +
        'Nếu có: implement integrity check (HMAC) trước khi deserialize. ' +
        'Ưu tiên chuyển sang JSON/Protobuf.',
      references: [
        'https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/',
        'https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html',
      ],
      collector: 'blackbox',
    }));
  }

  return findings;
}

module.exports = { runDeserializationHeuristic };
