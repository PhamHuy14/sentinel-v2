const path = require('path');
const { readTextSafe } = require('./project-loader');

function collectDependencyArtifacts(files) {
  const packageJson = files.find((f) => path.basename(f) === 'package.json');
  const packageLock = files.find((f) => path.basename(f) === 'package-lock.json');
  const csprojFiles = files.filter((f) => f.endsWith('.csproj'));
  return {
    packageJson: packageJson ? readTextSafe(packageJson) : '',
    packageJsonPath: packageJson || '',
    packageLockJson: packageLock ? readTextSafe(packageLock) : '',
    packageLockPath: packageLock || '',
    csprojFiles: csprojFiles.map((f) => ({ path: f, content: readTextSafe(f) }))
  };
}

module.exports = { collectDependencyArtifacts };
