// engine/scanner/param-intelligence.js
// ── Extended: path, file, template, cmd, nosql type detection

const PATTERNS = {
  EMAIL:  /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
  URL:    /^https?:\/\/[^\s]+$|^\/[^\s]+$/,
  TOKEN:  /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$|^[A-Fa-f0-9]{32,64}$/,
  NUMBER: /^-?\d+(\.\d+)?$/,
};

const KEY_HINTS = {
  EMAIL:    ['email', 'mail'],
  URL:      ['url', 'redirect', 'uri', 'next', 'return', 'link', 'target', 'dest', 'destination', 'callback', 'ref', 'referer', 'redir'],
  TOKEN:    ['token', 'jwt', 'auth', 'key', 'session', 'hash', 'apikey', 'api_key', 'secret'],
  NUMBER:   ['id', 'page', 'limit', 'count', 'offset', 'index', 'num', 'pid', 'uid', 'cid'],
  TEXT:     ['search', 'q', 'query', 'name', 'desc', 'description', 'title', 'msg', 'message', 'comment', 'content', 'text', 'input', 'keyword'],
  PATH:     ['path', 'file', 'filename', 'dir', 'folder', 'read', 'load', 'include', 'require', 'download', 'doc', 'document',  'attachment', 'view', 'page', 'template'],
  TEMPLATE: ['template', 'tpl', 'view', 'layout', 'format', 'render'],
  CMD:      ['cmd', 'exec', 'command', 'run', 'ping', 'host', 'ip', 'addr', 'address'],
};

/**
 * Detect parameter type from key name + value to select optimal payloads.
 * Priority: value pattern > key hint > value length heuristic
 */
function detectParamType(key = '', value = '') {
  key   = key.toLowerCase();
  value = (value || '').trim();

  // ── High-confidence value-based patterns ─────────────────
  if (PATTERNS.URL.test(value))   return 'url';
  if (PATTERNS.EMAIL.test(value)) return 'email';
  if (PATTERNS.TOKEN.test(value) && value.length >= 20) return 'token';
  if (PATTERNS.NUMBER.test(value) && value.length < 15)  return 'number';

  // ── Key-name hints ────────────────────────────────────────
  for (const hint of KEY_HINTS.URL)      { if (key.includes(hint)) return 'url'; }
  for (const hint of KEY_HINTS.EMAIL)    { if (key.includes(hint)) return 'email'; }
  for (const hint of KEY_HINTS.TOKEN)    { if (key.includes(hint)) return 'token'; }
  for (const hint of KEY_HINTS.PATH)     { if (key.includes(hint)) return 'path'; }
  for (const hint of KEY_HINTS.TEMPLATE) { if (key.includes(hint)) return 'template'; }
  for (const hint of KEY_HINTS.CMD)      { if (key.includes(hint)) return 'cmd'; }
  for (const hint of KEY_HINTS.NUMBER)   { if (key === hint || key.endsWith('_id')) return 'number'; }
  for (const hint of KEY_HINTS.TEXT)     { if (key.includes(hint)) return 'text'; }

  // ── Fallback: text if value is non-numeric string ────────
  if (value.length > 0 && isNaN(Number(value))) return 'text';

  return 'unknown';
}

module.exports = { detectParamType };
