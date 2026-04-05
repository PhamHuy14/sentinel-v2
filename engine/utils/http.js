const DEFAULT_HEADERS = {
  'User-Agent': 'OWASP2025Workbench/0.3',
  'Accept': 'text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8'
};

function parseCustomHeaders(customHeaders) {
  if (!customHeaders) return {};
  if (typeof customHeaders === 'object' && !Array.isArray(customHeaders)) return customHeaders;
  if (typeof customHeaders !== 'string') throw new Error('Custom headers phải là chuỗi JSON hoặc object.');
  const trimmed = customHeaders.trim();
  if (!trimmed) return {};
  try {
    const parsed = JSON.parse(trimmed);
    if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') throw new Error('Custom headers phải là JSON object.');
    return parsed;
  } catch (error) {
    throw new Error(`Custom headers JSON không hợp lệ: ${error.message}`);
  }
}

function buildRequestHeaders(auth = {}) {
  const headers = { ...DEFAULT_HEADERS };
  const custom = parseCustomHeaders(auth.customHeaders);
  Object.assign(headers, custom);
  if (auth.cookie?.trim()) headers.Cookie = auth.cookie.trim();
  if (auth.bearerToken?.trim()) headers.Authorization = `Bearer ${auth.bearerToken.trim()}`;
  else if (auth.authorization?.trim()) headers.Authorization = auth.authorization.trim();
  return headers;
}

function maskValue(value = '') {
  if (!value) return '';
  if (value.length <= 8) return '********';
  return `${value.slice(0, 4)}…${value.slice(-3)}`;
}

function summarizeAuth(auth = {}) {
  return {
    hasCookie: Boolean(auth.cookie?.trim()),
    hasBearerToken: Boolean(auth.bearerToken?.trim()),
    hasAuthorization: Boolean(auth.authorization?.trim()),
    hasCustomHeaders: Boolean(auth.customHeaders && String(auth.customHeaders).trim()),
    customHeaderKeys: Object.keys(parseCustomHeaders(auth.customHeaders || {})),
    maskedAuthorization: auth.authorization?.trim() ? maskValue(auth.authorization.trim()) : '',
    maskedBearerToken: auth.bearerToken?.trim() ? maskValue(auth.bearerToken.trim()) : ''
  };
}

const { ScannerHttpClient } = require('./http-client');

// Khởi tạo một client mặc định cho fetchWithMeta cũ để không lo hỏng logic các file chưa migrate hết
const defaultClient = new ScannerHttpClient({
  timeoutMs: 15000,
  maxRetries: 2,
  concurrency: 5,
  rejectUnauthorized: false // Dev override
});

async function fetchWithMeta(url, init = {}) {
  return await defaultClient.request(url, {
    headers: { ...DEFAULT_HEADERS, ...(init.headers || {}) },
    ...init
  });
}

function toHeaderObject(headers) {
  return Object.fromEntries(headers.entries());
}

module.exports = { DEFAULT_HEADERS, buildRequestHeaders, summarizeAuth, fetchWithMeta, toHeaderObject };
