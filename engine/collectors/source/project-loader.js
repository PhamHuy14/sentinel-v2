const fs = require('fs');
const path = require('path');

const DEFAULT_MAX_FILES = 2500;
const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'bin', 'obj', '.vs', 'coverage', '.next', '.nuxt']);

function parsePositiveInt(value, fallback) {
  const parsed = Number.parseInt(String(value ?? ''), 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function walkFiles(root, options = {}) {
  const maxFiles = typeof options === 'number'
    ? options
    : parsePositiveInt(options.maxFiles ?? process.env.SENTINEL_PROJECT_MAX_FILES, DEFAULT_MAX_FILES);
  const out = [];
  function walk(dir) {
    if (out.length >= maxFiles) return;
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue;
        walk(path.join(dir, entry.name));
      } else {
        out.push(path.join(dir, entry.name));
        if (out.length >= maxFiles) return;
      }
    }
  }
  walk(root);
  return out;
}

function readTextSafe(filePath, maxBytes = 250000) {
  try {
    const stat = fs.statSync(filePath);
    if (stat.size > maxBytes) return '';
    return fs.readFileSync(filePath, 'utf8');
  } catch {
    return '';
  }
}

module.exports = { walkFiles, readTextSafe };
