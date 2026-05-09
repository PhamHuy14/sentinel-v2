// engine/scanner/fuzzer.js
// ── Sentinel v2 — Active Fuzzer (nâng cấp: SSRF, Path Traversal, SSTI, Cmd Injection, timing SQLi, budget guard)

const { URL } = require('url');
const { detectParamType }   = require('./param-intelligence');
const { getPayloadsByType } = require('./payload-engine');
const {
  isReflectedXss,
  isSqlError,
  isSqlTiming,
  isOpenRedirect,
  isSsrfResponse,
  isPathTraversal,
  isSsti,
  isCommandInjection,
} = require('./analyzer');
const { verifySqli, verifyXss } = require('./verifier');
const { normalizeFinding }      = require('../models/finding');

// ── Hằng số ──────────────────────────────────────────────────────────────────
const PCONCUR   = 4;  // Số param URL test song song (trước đây là 3)
const SLEEP_SECS = 3; // Số giây dùng cho payload timing

// ── Hàm hỗ trợ ───────────────────────────────────────────────────────────────

/** Bộ chặn budget kiểu atomic: trừ trước khi await để tránh vượt ngưỡng */
function takeBudget(state) {
  if (state.budget <= 0) return false;
  state.budget--;
  return true;
}

/** Đo thời gian phản hồi gốc để so sánh cho timing attack */
async function measureBaseline(url, headers, client) {
  try {
    const r = await client.request(url, { headers });
    return r?.timeMs ?? 0;
  } catch {
    return 0;
  }
}

// ── Hàm export chính ──────────────────────────────────────────────────────────
async function runDynamicFuzzing(context, client, maxBudget = 20, onProgress, abortSignal) {
  const emit   = onProgress || (() => {});
  const state  = { budget: maxBudget }; // object mutable, dùng chung an toàn vì JS chạy đơn luồng
  const findings = [];
  const processedKeys = new Set();

  // ── PHẦN 1: FUZZ PARAM URL ────────────────────────────────────────────────
  const urlParamPairs = [];
  for (const link of context.links) {
    if (abortSignal?.aborted) break;
    try {
      const urlObj = new URL(link);
      if (urlObj.origin !== context.origin) continue;
      for (const [key, val] of urlObj.searchParams.entries()) {
        const sig = `GET:${urlObj.origin + urlObj.pathname}:${key}`;
        if (!processedKeys.has(sig)) { processedKeys.add(sig); urlParamPairs.push({ urlObj, key, val }); }
      }
    } catch {}
  }

  emit({ stage: 'fuzz', msg: `Param URL: tìm thấy ${urlParamPairs.length} tham số có thể inject`, level: 'info', ts: Date.now() });

  for (let i = 0; i < urlParamPairs.length; i += PCONCUR) {
    if (state.budget <= 0 || abortSignal?.aborted) break;
    await Promise.all(urlParamPairs.slice(i, i + PCONCUR).map(async ({ urlObj, key, val }) => {
      if (state.budget <= 0 || abortSignal?.aborted) return;
      const basePath  = urlObj.origin + urlObj.pathname;
      const paramType = detectParamType(key, val);
      const payloads  = getPayloadsByType(paramType, false);

      emit({ stage: 'fuzz', msg: `Đang test [GET] ${basePath} — param "${key}" (${paramType})`, level: 'info', ts: Date.now() });

      // Đo baseline để phát hiện timing attack
      const baselineMs = (paramType === 'number' || paramType === 'unknown')
        ? await measureBaseline(urlObj.toString(), context.requestHeaders, client)
        : 0;

      let isVulnerable = false;
      for (const payload of payloads) {
        if (state.budget <= 0 || isVulnerable || abortSignal?.aborted) break;
        if (!takeBudget(state)) break;

        const testUrl = new URL(urlObj.toString());
        testUrl.searchParams.set(key, payload);
        try {
          const res   = await client.request(testUrl.toString(), { headers: context.requestHeaders, signal: abortSignal });
          const found = await _analyzeResponse(res, payload, paramType, urlObj.toString(), key, 'url-param', client, context.requestHeaders, findings, emit, baselineMs, state, abortSignal);
          if (found) isVulnerable = true;
        } catch (e) {
          if (e.message?.includes('aborted') || abortSignal?.aborted) return;
        }
      }
    }));
  }

  // ── PHẦN 2: FUZZ FORM ─────────────────────────────────────────────────────
  const forms = context.forms || [];
  emit({ stage: 'fuzz', msg: `Fuzz form: phát hiện ${forms.length} biểu mẫu`, level: 'info', ts: Date.now() });

  for (const form of forms) {
    if (state.budget <= 0 || abortSignal?.aborted) break;
    let formAction = form.action || context.scannedUrl;
    if (formAction && !formAction.startsWith('http')) {
      try { formAction = new URL(formAction, context.origin).toString(); } catch { formAction = context.scannedUrl; }
    }
    const method = (form.method || 'get').toLowerCase();
    const inputs = form.inputs || [];

    for (const input of inputs) {
      if (state.budget <= 0 || abortSignal?.aborted) break;
      if (!input.name || ['submit', 'button', 'hidden', 'file', 'image'].includes(input.type)) continue;
      const key = input.name;
      const sig = `${method.toUpperCase()}:${formAction}:${key}`;
      if (processedKeys.has(sig)) continue;
      processedKeys.add(sig);

      const paramType = detectParamType(key, input.value || '');
      const payloads  = getPayloadsByType(paramType, false);

      emit({ stage: 'fuzz', msg: `Đang test [form ${method.toUpperCase()}] "${key}" (${paramType})`, level: 'info', ts: Date.now() });

      const baselineMs = (paramType === 'number' || paramType === 'unknown')
        ? await measureBaseline(formAction, context.requestHeaders, client)
        : 0;

      let isVulnerable = false;
      for (const payload of payloads) {
        if (state.budget <= 0 || isVulnerable || abortSignal?.aborted) break;
        if (!takeBudget(state)) break;

        const formData = {};
        inputs.forEach(i => { if (i.name) formData[i.name] = i.value || ''; });
        formData[key] = payload;
        try {
          let res;
          if (method === 'post') {
            res = await client.request(formAction, {
              method: 'POST',
              headers: { ...context.requestHeaders, 'Content-Type': 'application/x-www-form-urlencoded' },
              body: new URLSearchParams(formData).toString(),
              signal: abortSignal,
            });
          } else {
            const getUrl = new URL(formAction);
            Object.entries(formData).forEach(([k, v]) => getUrl.searchParams.set(k, v));
            res = await client.request(getUrl.toString(), { headers: context.requestHeaders, signal: abortSignal });
          }
          const found = await _analyzeResponse(res, payload, paramType, formAction, key, `form [${method.toUpperCase()}]`, client, context.requestHeaders, findings, emit, baselineMs, state, abortSignal);
          if (found) isVulnerable = true;
        } catch (e) {
          if (e.message?.includes('aborted') || abortSignal?.aborted) return;
        }
      }
    }
  }

  // ── PHẦN 3: INJECTION QUA HEADER (chỉ dùng phần budget nhỏ) ───────────────
  if (state.budget > 3 && !abortSignal?.aborted) {
    await _testHeaderInjection(context, client, state, findings, emit, abortSignal);
  }

  return findings;
}

// ── Bộ định tuyến phân tích phản hồi ──────────────────────────────────────────
async function _analyzeResponse(res, payload, paramType, targetUrl, key, location, client, reqHeaders, findings, emit, baselineMs, _state, _abortSignal) {
  if (!res) return false;

  // XSS
  if (paramType === 'text' || paramType === 'unknown') {
    if (isReflectedXss(res, payload)) {
      const confidence = await verifyXss(targetUrl, key, client, reqHeaders).catch(() => 'medium');
      _push(findings, emit, normalizeFinding({
        ruleId: 'A03-XSS-FUZZ', owaspCategory: 'A03',
        title: `Reflected XSS tại tham số '${key}'`,
        severity: 'high', confidence,
        target: targetUrl, location,
        evidence: [`Payload: ${payload}`, `Tham số '${key}' phản xạ dữ liệu chưa encode vào HTML response.`],
        remediation: 'Dùng cơ chế output encoding theo đúng ngữ cảnh. Đồng thời kiểm tra và siết chặt header Content-Security-Policy.',
        references: ['https://owasp.org/Top10/2025/A03_2025-Injection/'],
        collector: 'active-fuzzer',
      }));
      return true;
    }
  }

  // SQLi — dạng error-based
  if ((paramType === 'number' || paramType === 'unknown' || paramType === 'text') && !payload.includes('SLEEP') && !payload.includes('WAITFOR') && !payload.includes('pg_sleep')) {
    if (isSqlError(res)) {
      const confidence = await verifySqli(targetUrl, key, client, reqHeaders).catch(() => 'medium');
      _push(findings, emit, normalizeFinding({
        ruleId: 'A03-SQLI-ERROR', owaspCategory: 'A03',
        title: `SQL Injection (Error-based) tại tham số '${key}'`,
        severity: 'critical', confidence,
        target: targetUrl, location,
        evidence: [`Payload: ${payload}`, `Server trả về SQL error hoặc HTTP 500 khi inject vào '${key}'.`],
        remediation: 'Dùng Prepared Statements / Parameterized Queries. Không bao giờ để lộ lỗi DB thô ra ngoài.',
        references: ['https://owasp.org/Top10/2025/A03_2025-Injection/'],
        collector: 'active-fuzzer',
      }));
      return true;
    }
  }

  // SQLi — dạng time-based (chỉ áp dụng cho payload SLEEP/WAITFOR)
  if ((payload.includes('SLEEP') || payload.includes('WAITFOR') || payload.includes('pg_sleep')) && isSqlTiming(res, SLEEP_SECS, baselineMs)) {
    _push(findings, emit, normalizeFinding({
      ruleId: 'A03-SQLI-TIME', owaspCategory: 'A03',
      title: `SQL Injection (Time-based Blind) tại tham số '${key}'`,
      severity: 'critical', confidence: 'medium',
      target: targetUrl, location,
      evidence: [`Payload: ${payload}`, `Server phản hồi sau ${res.timeMs}ms (baseline: ${baselineMs}ms) — có khả năng time-based SQLi.`],
        remediation: 'Dùng truy vấn tham số hóa. Có thể bật WAF và giới hạn tần suất request để giảm nguy cơ khai thác.',
      references: ['https://owasp.org/Top10/2025/A03_2025-Injection/'],
      collector: 'active-fuzzer',
    }));
    return true;
  }

  // Open Redirect
  if (paramType === 'url') {
    if (isOpenRedirect(res, payload)) {
      _push(findings, emit, normalizeFinding({
        ruleId: 'A01-REDIRECT-FUZZ', owaspCategory: 'A01',
        title: `Lỗ hổng Open Redirect tại tham số '${key}'`,
        severity: 'medium', confidence: 'high',
        target: targetUrl, location,
        evidence: [`Payload: ${payload}`, `Server redirect sang domain ngoài, cho thấy có dấu hiệu Open Redirect.`],
        remediation: 'Validate URL đích, dùng whitelist, không trust giá trị người dùng cung cấp.',
        references: [],
        collector: 'active-fuzzer',
      }));
      return true;
    }
  }

  // SSRF
  if (paramType === 'url' || paramType === 'path') {
    if (isSsrfResponse(res)) {
      _push(findings, emit, normalizeFinding({
        ruleId: 'A10-SSRF-FUZZ', owaspCategory: 'A10',
        title: `Lỗ hổng SSRF tại tham số '${key}'`,
        severity: 'critical', confidence: 'high',
        target: targetUrl, location,
        evidence: [`Payload: ${payload}`, `Response chứa cloud metadata hoặc internal IP — SSRF đã khai thác được.`],
        remediation: 'Validate và whitelist URL đích. Dùng DNS rebinding protection. Block nội mạng từ server.',
        references: ['https://owasp.org/Top10/2025/A10_2025-SSRF/'],
        collector: 'active-fuzzer',
      }));
      return true;
    }
  }

  // Path Traversal
  if (paramType === 'path') {
    if (isPathTraversal(res)) {
      _push(findings, emit, normalizeFinding({
        ruleId: 'A01-PATH-TRAVERSAL-FUZZ', owaspCategory: 'A01',
        title: `Lỗ hổng Path Traversal tại tham số '${key}'`,
        severity: 'high', confidence: 'high',
        target: targetUrl, location,
        evidence: [`Payload: ${payload}`, `Response chứa nội dung file hệ thống (vd: /etc/passwd, win.ini).`],
        remediation: 'Canonicalize đường dẫn, enforce allowlist, dùng chroot/sandbox.',
        references: ['https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/'],
        collector: 'active-fuzzer',
      }));
      return true;
    }
  }

  // SSTI
  if (paramType === 'template' || paramType === 'text') {
    if (isSsti(res, payload)) {
      _push(findings, emit, normalizeFinding({
        ruleId: 'A03-SSTI-FUZZ', owaspCategory: 'A03',
        title: `Server-Side Template Injection (SSTI) tại tham số '${key}'`,
        severity: 'critical', confidence: 'high',
        target: targetUrl, location,
        evidence: [`Payload: ${payload}`, `Server đã evaluate biểu thức template — RCE có thể khai thác đƣợc.`],
        remediation: 'Không render user input qua template engine. Dùng sandbox hoặc static templates.',
        references: ['https://owasp.org/Top10/2025/A03_2025-Injection/'],
        collector: 'active-fuzzer',
      }));
      return true;
    }
  }

  // Command Injection
  if (paramType === 'cmd') {
    if (isCommandInjection(res)) {
      _push(findings, emit, normalizeFinding({
        ruleId: 'A03-CMDI-FUZZ', owaspCategory: 'A03',
        title: `Lỗ hổng Command Injection tại tham số '${key}'`,
        severity: 'critical', confidence: 'high',
        target: targetUrl, location,
        evidence: [`Payload: ${payload}`, `Response chứa output của lệnh hệ thống (id/ls/whoami).`],
        remediation: 'Không truyền user input vào shell. Dùng allowlist ký tự, escape hoặc thư viện subprocess an toàn.',
        references: ['https://owasp.org/Top10/2025/A03_2025-Injection/'],
        collector: 'active-fuzzer',
      }));
      return true;
    }
  }

  return false;
}

// ── Header Injection Probe ────────────────────────────────────────────────────
async function _testHeaderInjection(context, client, state, findings, emit, abortSignal) {
  const INJECTABLE_HEADERS = [
    { header: 'X-Forwarded-For',  payload: '169.254.169.254' },
    { header: 'X-Forwarded-Host', payload: 'evil.example.com' },
    { header: 'X-Original-URL',   payload: '/admin' },
    { header: 'X-Rewrite-URL',    payload: '/admin' },
    { header: 'Referer',          payload: 'http://169.254.169.254/' },
  ];

  emit({ stage: 'fuzz', msg: `Header injection: testing ${INJECTABLE_HEADERS.length} security headers…`, level: 'info', ts: Date.now() });

  for (const { header, payload } of INJECTABLE_HEADERS) {
    if (state.budget <= 0 || abortSignal?.aborted) break;
    if (!takeBudget(state)) break;
    try {
      const res = await client.request(context.scannedUrl, {
        headers: { ...context.requestHeaders, [header]: payload },
        signal: abortSignal,
      });

      if (res && isSsrfResponse(res)) {
        _push(findings, emit, normalizeFinding({
          ruleId: 'A10-HEADER-SSRF', owaspCategory: 'A10',
          title: `Header-based SSRF qua ${header}`,
          severity: 'high', confidence: 'medium',
          target: context.scannedUrl, location: `header: ${header}`,
          evidence: [`Header: ${header}: ${payload}`, `Response chứa metadata nội bộ — SSRF qua HTTP header.`],
          remediation: 'Validate và strip proxy headers. Không tin tưởng X-Forwarded-* từ client.',
          references: ['https://owasp.org/Top10/2025/A10_2025-SSRF/'],
          collector: 'active-fuzzer',
        }));
      }
    } catch (e) {
      if (abortSignal?.aborted) break;
    }
  }
}

function _push(findings, emit, f) {
  findings.push(f);
  emit({ stage: 'found', msg: `⚠ ${f.ruleId}: ${f.title}`, level: 'warn', ts: Date.now() });
}

module.exports = { runDynamicFuzzing };
