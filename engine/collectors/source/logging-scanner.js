const { readTextSafe } = require('./project-loader');

const DEFAULT_MAX_CODE_FILES = 1000;

function maxCodeFiles() {
  const parsed = Number.parseInt(process.env.SENTINEL_PROJECT_MAX_CODE_FILES || '', 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : DEFAULT_MAX_CODE_FILES;
}

function collectCodeFiles(files) {
  return files
    .filter((f) => /\.(cs|js|ts|tsx|jsx|py|java|go|php)$/i.test(f))
    .slice(0, maxCodeFiles())
    .map((f) => ({ path: f, content: readTextSafe(f) }));
}

module.exports = { collectCodeFiles };
