const { normalizeFinding } = require('../../models/finding');

/**
 * Phát hiện dấu hiệu Command Injection / OS Command Exposure
 * Tham chiếu OWASP WSTG: WSTG-INPV-12
 *
 * Nâng cấp so với bản gốc:
 *  1. Mở rộng mẫu nhận diện output lệnh Windows (ipconfig, tasklist, dir, net user)
 *  2. Thêm nhận diện output lệnh Unix/Linux phổ biến (id, whoami, uname, cat /etc/hostname)
 *  3. Thêm nhận diện RCE qua Java (Runtime.exec output leak)
 *  4. Phân tách thành 2 mức độ: critical (output rõ ràng) và high (dấu hiệu mờ)
 *  5. Thu thập nhiều evidence hơn thay vì dừng ở match đầu tiên
 */

// Pattern mức CRITICAL: Output lệnh OS rõ ràng, hầu như không có false positive
const CRITICAL_PATTERNS = [
  // Unix /etc/passwd
  { re: /root:x:0:0:/,                label: 'Linux /etc/passwd — dòng root' },
  { re: /daemon:x:\d+:\d+/,           label: 'Linux /etc/passwd — dòng daemon' },
  { re: /nobody:x:\d+:\d+/,           label: 'Linux /etc/passwd — dòng nobody' },
  { re: /\/bin\/bash|\/bin\/sh|\/usr\/sbin\/nologin/, label: 'Linux /etc/passwd — đường dẫn shell' },

  // Unix command output signatures
  { re: /uid=\d+\(\w+\)\s+gid=\d+/,  label: 'Đầu ra lệnh `id` của Linux (uid=NNN(user) gid=NNN)' },
  { re: /Linux\s+\S+\s+\d+\.\d+\.\d+-\S+\s+#\d+/i, label: 'Đầu ra lệnh `uname -a` của Linux' },

  // Windows command output signatures
  { re: /cmd\.exe/i,                  label: 'Tham chiếu cmd.exe của Windows trong response' },
  { re: /powershell(?:\.exe)?/i,      label: 'Tham chiếu PowerShell của Windows trong response' },
  { re: /Windows IP Configuration/i,  label: 'Đầu ra lệnh `ipconfig` của Windows' },
  { re: /Subnet Mask\s*[.:]\s*255\./i, label: 'Windows `ipconfig` — dòng Subnet Mask' },
  { re: /\bImage Name\b.*\bMem Usage\b/i, label: 'Header đầu ra lệnh `tasklist` của Windows' },
  { re: /\bC:\\Windows\\System32\b/i, label: 'Đường dẫn Windows System32 trong response' },
  { re: /\bNT AUTHORITY\\SYSTEM\b/i,  label: 'Tài khoản Windows SYSTEM — đặc quyền cao' },
  { re: /\bnet localgroup administrators\b/i, label: 'Đầu ra lệnh `net localgroup` của Windows' },
];

// Pattern mức HIGH: Dấu hiệu command injection nhưng có thể có false positive thấp
const HIGH_PATTERNS = [
  { re: /\bwhoami\b.*\n?\w+\\\w+/i,  label: 'Đầu ra lệnh `whoami` của Windows (domain\\user)' },
  { re: /Directory of [A-Z]:\\/i,     label: 'Đầu ra lệnh `dir` của Windows' },
  { re: /Volume in drive [A-Z] /i,    label: 'Windows `dir` — dòng Volume' },
  { re: /\d+ File\(s\)\s+[\d,]+ bytes/i, label: 'Windows `dir` — dòng file count' },
  { re: /\/proc\/\d+\/cmdline|\/proc\/version/i, label: 'Lộ thông tin Linux /proc filesystem' },
  // Java process info leakage
  { re: /java\.lang\.Runtime|ProcessBuilder|Runtime\.getRuntime\(\)\.exec/i, label: 'Tham chiếu Java Runtime.exec trong response' },
  // Python subprocess
  { re: /subprocess\.(call|run|Popen)|os\.system\(/i, label: 'Tham chiếu Python subprocess/os.system trong response' },
];

function runCommandInjectionHeuristic(context) {
  const text = context.text || '';
  const findings = [];

  // Kiểm tra CRITICAL patterns
  const criticalMatches = CRITICAL_PATTERNS.filter(({ re }) => re.test(text));
  if (criticalMatches.length > 0) {
    findings.push(normalizeFinding({
      ruleId: 'A05-CMD-001',
      owaspCategory: 'A05',
      title: 'Phát hiện output lệnh OS trong response — Command Injection khả năng cao',
      severity: 'critical',
      confidence: 'high',
      target: context.finalUrl,
      location: 'response body',
      evidence: criticalMatches.map(m => m.label),
      remediation:
        'Loại bỏ shell invocation dựa trên input người dùng. ' +
        'Dùng allowlist tham số, parameterized command API (không concat string). ' +
        'Chạy process với minimum privilege (non-root). ' +
        'Không bao giờ trả về output của OS command cho client.',
      references: [
        'https://owasp.org/Top10/2025/A05_2025-Injection/',
        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection',
        'https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html',
      ],
      collector: 'blackbox',
    }));
  }

  // Kiểm tra HIGH patterns (chỉ nếu chưa có finding critical cho cùng target)
  if (criticalMatches.length === 0) {
    const highMatches = HIGH_PATTERNS.filter(({ re }) => re.test(text));
    if (highMatches.length > 0) {
      findings.push(normalizeFinding({
        ruleId: 'A05-CMD-002',
        owaspCategory: 'A05',
        title: 'Có dấu hiệu mờ của command injection hoặc lộ thông tin hệ điều hành',
        severity: 'high',
        confidence: 'low',
        target: context.finalUrl,
        location: 'response body',
        evidence: highMatches.map(m => m.label),
        remediation:
          'Xem xét kỹ nội dung response để xác nhận OS command output. ' +
          'Sanitize tất cả input đưa vào shell command. Dùng execFile() thay execSync().',
        references: [
          'https://owasp.org/Top10/2025/A05_2025-Injection/',
          'https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html',
        ],
        collector: 'blackbox',
      }));
    }
  }

  return findings;
}

module.exports = { runCommandInjectionHeuristic };
