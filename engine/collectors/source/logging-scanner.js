const { readTextSafe } = require('./project-loader');

function collectCodeFiles(files) {
  return files
    .filter((f) => /\.(cs|js|ts|tsx|jsx|py|java|go|php)$/i.test(f))
    .slice(0, 200)
    .map((f) => ({ path: f, content: readTextSafe(f) }));
}

module.exports = { collectCodeFiles };
