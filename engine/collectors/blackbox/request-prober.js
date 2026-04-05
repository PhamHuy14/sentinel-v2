const { fetchWithMeta, buildRequestHeaders } = require('../../utils/http');

async function probeOptions(url, auth = {}) {
  try {
    const response = await fetch(url, { method: 'OPTIONS', headers: buildRequestHeaders(auth) });
    return { allow: response.headers.get('allow') || '', status: response.status };
  } catch {
    return { allow: '', status: 0 };
  }
}

async function probeMissingPath(origin, auth = {}) {
  try {
    const badUrl = `${origin.replace(/\/$/, '')}/this-path-should-not-exist-security-scan`;
    const result = await fetchWithMeta(badUrl, { headers: buildRequestHeaders(auth) });
    return { url: badUrl, ...result };
  } catch {
    return null;
  }
}

async function probeVariant(url, variant, auth = {}) {
  return fetchWithMeta(url, {
    headers: { ...buildRequestHeaders(auth), ...(variant.headers || {}) },
    method: variant.method || 'GET'
  });
}

module.exports = { probeOptions, probeMissingPath, probeVariant };
