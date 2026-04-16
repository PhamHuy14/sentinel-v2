// BUG FIX: probeOptions và probeMissingPath đã bị truyền `client` từ scan-engine.js
// nhưng cả hai hàm chỉ nhận 2 tham số — bỏ qua hoàn toàn `client`, dùng global fetch/fetchWithMeta.
// Hậu quả: probe không đi qua ScannerHttpClient → sai timeout, không có concurrency limit,
// không có retry logic, và không phản ánh cấu hình scan của người dùng.
// FIX: thêm tham số `client` và dùng nó thay vì global fetch.

const { fetchWithMeta, buildRequestHeaders } = require('../../utils/http');

/**
 * @param {string} url
 * @param {object} auth
 * @param {import('../../utils/http-client').ScannerHttpClient} [client]
 */
async function probeOptions(url, auth = {}, client) {
  try {
    if (client) {
      const res = await client.request(url, {
        method: 'OPTIONS',
        headers: buildRequestHeaders(auth),
        redirect: 'manual',
      });
      return {
        allow: res.response.headers.get('allow') || '',
        status: res.response.status,
      };
    }
    // Fallback: nếu không có client (backward-compat)
    const response = await fetch(url, {
      method: 'OPTIONS',
      headers: buildRequestHeaders(auth),
    });
    return { allow: response.headers.get('allow') || '', status: response.status };
  } catch {
    return { allow: '', status: 0 };
  }
}

/**
 * @param {string} origin
 * @param {object} auth
 * @param {import('../../utils/http-client').ScannerHttpClient} [client]
 */
async function probeMissingPath(origin, auth = {}, client) {
  try {
    const badUrl = `${origin.replace(/\/$/, '')}/this-path-should-not-exist-security-scan`;
    if (client) {
      const result = await client.request(badUrl, {
        headers: buildRequestHeaders(auth),
        redirect: 'follow',
      });
      return { url: badUrl, ...result };
    }
    // Fallback
    const result = await fetchWithMeta(badUrl, { headers: buildRequestHeaders(auth) });
    return { url: badUrl, ...result };
  } catch {
    return null;
  }
}

async function probeVariant(url, variant, auth = {}) {
  return fetchWithMeta(url, {
    headers: { ...buildRequestHeaders(auth), ...(variant.headers || {}) },
    method: variant.method || 'GET',
  });
}

module.exports = { probeOptions, probeMissingPath, probeVariant };
