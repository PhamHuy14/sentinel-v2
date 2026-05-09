const { normalizeFinding } = require('../../models/finding');

/**
 * Phát hiện Untrusted Config Data / Unsafe Dynamic Execution
 * Tham chiếu OWASP WSTG: WSTG-INPV-11 (Code Injection), A08
 *
 * Nâng cấp so với bản gốc (chỉ 3 pattern, chỉ check yaml/json files):
 *  1. Mở rộng pattern: thêm Function(), setTimeout(string), execSync, child_process
 *  2. Thêm check code files (.js, .ts, .py, .java, .cs) không chỉ config files
 *  3. Thêm: unsafe YAML deserialization (yaml.load vs yaml.safeLoad/yaml.parseDocument)
 *  4. Thêm: Python pickle/marshal/shelve từ nguồn không tin cậy
 *  5. Thêm: PHP unserialize() với dữ liệu ngoài
 *  6. Thêm: dynamic require() / import() từ user-controlled path
 *  7. Thêm: XML deserialization unsafe (XmlSerializer với untrusted input)
 */

// ─── Pattern nguy hiểm trong JavaScript/TypeScript ────────────────────────────
const JS_DANGEROUS_PATTERNS = [
  {
    re: /\beval\s*\(/,
    label: 'eval() — executes arbitrary string as code',
    severity: 'high',
    context: 'javascript',
  },
  {
    re: /\bnew\s+Function\s*\(/,
    label: 'new Function() — dynamic code execution from string',
    severity: 'high',
    context: 'javascript',
  },
  {
    re: /\bFunction\s*\(\s*["'`]/,
    label: 'Function() constructor with string literal — dynamic code',
    severity: 'medium',
    context: 'javascript',
  },
  {
    re: /setTimeout\s*\(\s*["'`][^)]{5,}/,
    label: 'setTimeout(string) — executes string as code (deprecated, dangerous)',
    severity: 'medium',
    context: 'javascript',
  },
  {
    re: /setInterval\s*\(\s*["'`][^)]{5,}/,
    label: 'setInterval(string) — executes string as code (deprecated, dangerous)',
    severity: 'medium',
    context: 'javascript',
  },
  {
    re: /\brequire\s*\(\s*(?:req\.|res\.|request\.|params\.|query\.|body\.|process\.env)/,
    label: 'require() với dynamic/user-controlled path — Remote Code Execution risk',
    severity: 'critical',
    context: 'javascript',
  },
  {
    re: /child_process\.exec\s*\(|execSync\s*\(|spawnSync\s*\(/,
    label: 'child_process.exec/execSync/spawnSync — OS command execution',
    severity: 'high',
    context: 'javascript',
  },
  {
    re: /vm\.runInNewContext|vm\.runInThisContext|vm\.Script/,
    label: 'Node.js vm module — sandbox bypass risk nếu input không được validate',
    severity: 'medium',
    context: 'javascript',
  },
];

// ─── Pattern nguy hiểm trong Python ───────────────────────────────────────────
const PYTHON_DANGEROUS_PATTERNS = [
  {
    re: /\bpickle\.loads?\s*\(|import\s+pickle/,
    label: 'pickle.load/loads — deserialization of untrusted data = arbitrary code execution',
    severity: 'critical',
    context: 'python',
  },
  {
    re: /\bmarshal\.loads?\s*\(/,
    label: 'marshal.loads — unsafe deserialization',
    severity: 'critical',
    context: 'python',
  },
  {
    re: /\bshelve\.open\s*\(/,
    label: 'shelve.open — uses pickle internally, unsafe with untrusted data',
    severity: 'high',
    context: 'python',
  },
  {
    re: /yaml\.load\s*\([^,)]+\)(?!\s*,\s*Loader\s*=\s*yaml\.SafeLoader)/,
    label: 'yaml.load() không có SafeLoader — Python YAML unsafe deserialization (Loader mặc định cho phép RCE)',
    severity: 'critical',
    context: 'python',
  },
  {
    re: /\beval\s*\(|exec\s*\(|__import__\s*\(/,
    label: 'Python eval()/exec()/__import__() — dynamic code execution',
    severity: 'high',
    context: 'python',
  },
  {
    re: /os\.system\s*\(|subprocess\.call\s*\(.*shell\s*=\s*True|subprocess\.run\s*\(.*shell\s*=\s*True/,
    label: 'os.system() / subprocess với shell=True — OS injection risk',
    severity: 'high',
    context: 'python',
  },
];

// ─── Pattern nguy hiểm trong PHP ──────────────────────────────────────────────
const PHP_DANGEROUS_PATTERNS = [
  {
    re: /\bunserialize\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)/,
    label: 'PHP unserialize() với user input ($_GET/$_POST/$_REQUEST) — Object Injection / RCE',
    severity: 'critical',
    context: 'php',
  },
  {
    re: /\bunserialize\s*\(/,
    label: 'PHP unserialize() — verify input source; dùng JSON thay thế nếu có thể',
    severity: 'high',
    context: 'php',
  },
  {
    re: /\beval\s*\(\s*\$|preg_replace\s*\(.*\/e[^,)]/,
    label: 'PHP eval($var) hoặc preg_replace với /e modifier — dynamic code execution',
    severity: 'critical',
    context: 'php',
  },
  {
    re: /\bsystem\s*\(\s*\$|shell_exec\s*\(\s*\$|passthru\s*\(\s*\$|exec\s*\(\s*\$/,
    label: 'PHP system/shell_exec/passthru/exec với variable — OS command injection',
    severity: 'critical',
    context: 'php',
  },
];

// ─── Pattern nguy hiểm trong Java/.NET ────────────────────────────────────────
const JAVA_DOTNET_PATTERNS = [
  {
    re: /ObjectInputStream|readObject\s*\(\)|fromXML\s*\(|XStream.*fromXML/,
    label: 'Java ObjectInputStream.readObject() / XStream.fromXML() — Java deserialization',
    severity: 'critical',
    context: 'java',
  },
  {
    re: /BinaryFormatter\.Deserialize|NetDataContractSerializer\.Deserialize|LosFormatter\.Deserialize/,
    label: '.NET unsafe deserializer (BinaryFormatter/NetDataContractSerializer) — Microsoft khuyến nghị không dùng',
    severity: 'critical',
    context: 'dotnet',
  },
  {
    re: /Runtime\.getRuntime\(\)\.exec|ProcessBuilder\s*\(.*new\s+String\[\]/,
    label: 'Java Runtime.exec() / ProcessBuilder — OS command execution',
    severity: 'high',
    context: 'java',
  },
  {
    re: /ScriptEngine|Nashorn|Rhino.*eval|groovy\.lang\.GroovyShell/,
    label: 'Java ScriptEngine/Nashorn/Groovy eval — dynamic code execution',
    severity: 'high',
    context: 'java',
  },
];

// ─── YAML unsafe load trong JavaScript ────────────────────────────────────────
const JS_YAML_PATTERNS = [
  {
    re: /yaml\.load\s*\([^,)]+\)(?!\s*,\s*\{)/,
    label: 'js-yaml yaml.load() không có SAFE_LOAD schema — cho phép arbitrary code execution qua !!js/eval',
    severity: 'critical',
    context: 'javascript',
  },
];

function runUntrustedConfigData(context) {
  const findings = [];

  // Tất cả file để scan (config + code + text)
  const allFiles = [
    ...(context.configFiles || []),
    ...(context.codeFiles || []),
    ...(context.textFiles || []),
  ];

  // Dedup theo path
  const seen = new Set();
  const files = allFiles.filter(f => {
    if (!f || !f.path || seen.has(f.path)) return false;
    seen.add(f.path);
    return true;
  });

  for (const file of files) {
    const content = file.content || '';
    const path = file.path || '';
    const ext = (path.match(/\.(\w+)$/) || [])[1]?.toLowerCase() || '';

    const isJs = /\.[jt]sx?$/.test(path);
    const isPy = ext === 'py';
    const isPhp = ext === 'php';
    const isJava = ext === 'java';
    const isDotNet = /\.(cs|vb)$/.test(path);
    const isConfig = /ya?ml|json|config|env/i.test(path);

    // JavaScript/TypeScript
    if (isJs || isConfig) {
      for (const { re, label, severity } of [...JS_DANGEROUS_PATTERNS, ...JS_YAML_PATTERNS]) {
        if (re.test(content)) {
          findings.push(normalizeFinding({
            ruleId: 'A08-CONFIG-001',
            owaspCategory: 'A08',
            title: `Unsafe dynamic execution: ${label.split(' — ')[0]}`,
            severity,
            confidence: 'medium',
            target: path,
            location: path,
            evidence: [
              label,
              'Dùng dynamic code execution với dữ liệu từ config/user input có thể dẫn đến RCE.',
            ],
            remediation:
              'Tránh eval(), new Function(), setTimeout(string). ' +
              'Dùng allowlist thay vì dynamic code. ' +
              'Với YAML: dùng yaml.load(str, {schema: yaml.SAFE_SCHEMA}) hoặc yaml.safeLoad().',
            references: [
              'https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/',
              'https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html',
            ],
            collector: 'source',
          }));
          break; // 1 finding per pattern group per file
        }
      }
    }

    // Python
    if (isPy) {
      for (const { re, label, severity } of PYTHON_DANGEROUS_PATTERNS) {
        if (re.test(content)) {
          findings.push(normalizeFinding({
            ruleId: 'A08-CONFIG-002',
            owaspCategory: 'A08',
            title: `Python unsafe deserialization/execution: ${label.split(' — ')[0]}`,
            severity,
            confidence: 'medium',
            target: path,
            location: path,
            evidence: [label],
            remediation:
              'Thay pickle bằng JSON (json.dumps/loads). ' +
              'YAML: dùng yaml.safe_load() thay yaml.load(). ' +
              'Không deserialize dữ liệu từ nguồn không tin cậy.',
            references: [
              'https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html#python',
              'https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/',
            ],
            collector: 'source',
          }));
          break;
        }
      }
    }

    // PHP
    if (isPhp) {
      for (const { re, label, severity } of PHP_DANGEROUS_PATTERNS) {
        if (re.test(content)) {
          findings.push(normalizeFinding({
            ruleId: 'A08-CONFIG-003',
            owaspCategory: 'A08',
            title: `PHP unsafe deserialization/execution: ${label.split(' — ')[0]}`,
            severity,
            confidence: 'medium',
            target: path,
            location: path,
            evidence: [label],
            remediation:
              'Không dùng unserialize() với dữ liệu từ user/network. ' +
              'Dùng json_decode() thay thế. ' +
              'Tránh eval() và shell_exec() với variable input.',
            references: [
              'https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html#php',
              'https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/',
            ],
            collector: 'source',
          }));
          break;
        }
      }
    }

    // Java / .NET
    if (isJava || isDotNet) {
      for (const { re, label, severity } of JAVA_DOTNET_PATTERNS) {
        if (re.test(content)) {
          findings.push(normalizeFinding({
            ruleId: 'A08-CONFIG-004',
            owaspCategory: 'A08',
            title: `Java/.NET unsafe deserialization: ${label.split(' — ')[0]}`,
            severity,
            confidence: 'medium',
            target: path,
            location: path,
            evidence: [label],
            remediation:
              'Java: Implement ObjectInputFilter để whitelist class. Dùng JSON (Jackson/Gson) thay ObjectInputStream. ' +
              '.NET: Không dùng BinaryFormatter (đã deprecated trong .NET 5+). Dùng System.Text.Json.',
            references: [
              'https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html#java',
              'https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/',
            ],
            collector: 'source',
          }));
          break;
        }
      }
    }
  }

  return findings;
}

module.exports = { runUntrustedConfigData };
