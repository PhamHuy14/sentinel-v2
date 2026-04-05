const { readTextSafe } = require('./project-loader');

function collectTextFiles(files) {
  return files.slice(0, 200).map((f) => ({ path: f, content: readTextSafe(f) }));
}

module.exports = { collectTextFiles };
