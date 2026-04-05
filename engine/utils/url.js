const { URL } = require('url');

function ensureHttpUrl(input) {
  const trimmed = (input || '').trim();
  if (!trimmed) throw new Error('Hãy nhập URL cần quét.');
  const value = /^https?:\/\//i.test(trimmed) ? trimmed : `http://${trimmed}`;
  const parsed = new URL(value);
  if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('Chỉ hỗ trợ HTTP hoặc HTTPS.');
  return parsed;
}

module.exports = { ensureHttpUrl };
