const fs = require('fs');
const path = require('path');

function parseVersion(input) {
  if (!input) return null;
  const cleaned = String(input).trim().replace(/^v/, '');
  const parts = cleaned.split('.').map((p) => parseInt(p, 10));
  return {
    major: Number.isFinite(parts[0]) ? parts[0] : 0,
    minor: Number.isFinite(parts[1]) ? parts[1] : 0,
    patch: Number.isFinite(parts[2]) ? parts[2] : 0,
  };
}

function compareVersions(a, b) {
  if (a.major !== b.major) return a.major - b.major;
  if (a.minor !== b.minor) return a.minor - b.minor;
  return a.patch - b.patch;
}

function checkComparator(version, comparator) {
  const m = String(comparator).trim().match(/^(>=|<=|>|<|=)?\s*(\d+(?:\.\d+){0,2})$/);
  if (!m) return true;

  const op = m[1] || '=';
  const target = parseVersion(m[2]);
  const cmp = compareVersions(version, target);

  if (op === '>=') return cmp >= 0;
  if (op === '<=') return cmp <= 0;
  if (op === '>') return cmp > 0;
  if (op === '<') return cmp < 0;
  return cmp === 0;
}

function checkRange(versionText, rangeText) {
  const version = parseVersion(versionText);
  if (!version || !rangeText) return true;
  const comparators = String(rangeText).split(/\s+/).filter(Boolean);
  return comparators.every((c) => checkComparator(version, c));
}

function readNpmVersionFromUserAgent() {
  const ua = process.env.npm_config_user_agent || '';
  const match = ua.match(/npm\/(\d+(?:\.\d+){0,2})/i);
  return match ? match[1] : null;
}

function main() {
  const packageJsonPath = path.resolve(__dirname, '..', 'package.json');
  const pkg = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));

  const requiredNode = pkg.engines && pkg.engines.node;
  const requiredNpm = pkg.engines && pkg.engines.npm;

  const currentNode = process.version.replace(/^v/, '');
  const currentNpm = readNpmVersionFromUserAgent() || process.env.npm_version || '';

  const nodeOk = requiredNode ? checkRange(currentNode, requiredNode) : true;
  const npmOk = requiredNpm ? checkRange(currentNpm, requiredNpm) : true;

  if (nodeOk && npmOk) {
    process.stdout.write('Engine check passed.\n');
    return;
  }

  const lines = ['Engine check failed.'];
  if (!nodeOk) {
    lines.push(`- node required: ${requiredNode}, current: ${currentNode}`);
  }
  if (!npmOk) {
    lines.push(`- npm required: ${requiredNpm}, current: ${currentNpm || 'unknown'}`);
  }
  process.stderr.write(`${lines.join('\n')}\n`);
  process.exit(1);
}

main();
