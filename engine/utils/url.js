const { URL } = require('url');
const dns = require('dns/promises');
const net = require('net');

function ensureHttpUrl(input) {
  const trimmed = (input || '').trim();
  if (!trimmed) throw new Error('Hãy nhập URL cần quét.');
  const value = /^https?:\/\//i.test(trimmed) ? trimmed : `http://${trimmed}`;
  const parsed = new URL(value);
  if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('Chỉ hỗ trợ HTTP hoặc HTTPS.');
  return parsed;
}

function isPrivateIp(ip) {
  if (!ip) return true;
  const version = net.isIP(ip);
  if (version === 4) {
    const parts = ip.split('.').map(Number);
    const n = ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
    const inRange = (base, mask) => (n & mask) === (base & mask);
    return (
      inRange(0x00000000, 0xff000000) ||
      inRange(0x0a000000, 0xff000000) ||
      inRange(0x7f000000, 0xff000000) ||
      inRange(0xa9fe0000, 0xffff0000) ||
      inRange(0xac100000, 0xfff00000) ||
      inRange(0xc0a80000, 0xffff0000) ||
      inRange(0xe0000000, 0xf0000000) ||
      inRange(0xf0000000, 0xf0000000)
    );
  }
  if (version === 6) {
    const v = ip.toLowerCase();
    return (
      v === '::1' ||
      v === '::' ||
      v.startsWith('fc') ||
      v.startsWith('fd') ||
      v.startsWith('fe80:') ||
      v.startsWith('ff')
    );
  }
  return true;
}

async function validatePublicHttpUrl(url, options = {}) {
  const parsed = ensureHttpUrl(url);
  if (options.allowPrivate) return parsed;

  const host = parsed.hostname;
  const records = net.isIP(host)
    ? [{ address: host }]
    : await dns.lookup(host, { all: true, verbatim: true });
  if (!records.length) throw new Error('Không thể resolve hostname cần quét.');

  const blocked = records.find((record) => isPrivateIp(record.address));
  if (blocked) {
    throw new Error(`Target bị chặn vì resolve tới địa chỉ private/reserved (${blocked.address}). Bật SENTINEL_ALLOW_PRIVATE_TARGETS=true nếu bạn có ý quét môi trường nội bộ.`);
  }
  return parsed;
}

module.exports = { ensureHttpUrl, validatePublicHttpUrl, isPrivateIp };
