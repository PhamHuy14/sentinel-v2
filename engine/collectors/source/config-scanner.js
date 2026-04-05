const path = require('path');
const { readTextSafe } = require('./project-loader');

function collectConfigFiles(files) {
  return files
    .filter((f) => /appsettings|launchSettings|dockerfile|docker-compose|ya?ml|json/i.test(path.basename(f)))
    .slice(0, 60)
    .map((f) => ({ path: f, content: readTextSafe(f) }));
}

function collectCiFiles(files) {
  return files
    .filter(f => /\.github\/workflows|\.gitlab-ci\.ya?ml|jenkinsfile|\.circleci\/config/i.test(f))
    .slice(0, 20)
    .map(f => ({ path: f, content: readTextSafe(f) }));
}

module.exports = { collectConfigFiles, collectCiFiles };
