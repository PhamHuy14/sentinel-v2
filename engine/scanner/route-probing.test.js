import { describe, expect, it } from 'vitest';
import { _internals } from './scan-engine.js';

const { classifyProbeRoute, computeAttackSurface } = _internals;

describe('route probing verification', () => {
  it('does not treat SPA fallback HTML as exposed .env or .git content', () => {
    const shell = '<html><head><title>Demo SPA</title></head><body><app-root></app-root><script src="main.123.js"></script></body></html>';

    expect(classifyProbeRoute('/.env', 200, 'text/html', shell)).toMatchObject({
      isExposed: false,
    });
    expect(classifyProbeRoute('/.git/config', 200, 'text/html', shell)).toMatchObject({
      isExposed: false,
    });
  });

  it('confirms real sensitive responses by content signature', () => {
    expect(classifyProbeRoute('/.env', 200, 'text/plain', 'DB_PASSWORD=secret')).toMatchObject({
      isExposed: true,
    });
    expect(classifyProbeRoute('/ftp', 200, 'text/html', '<title>listing directory /ftp</title><a href="acquisitions.md">x</a>')).toMatchObject({
      isExposed: true,
    });
  });

  it('attack surface score ignores unconfirmed fallback routes', () => {
    const surface = computeAttackSurface({
      '/.env': { status: 200, isExposed: false },
      '/ftp': { status: 200, isExposed: true },
    }, 0, 0);

    expect(surface.exposedRoutes.map((route) => route.route)).toEqual(['/ftp']);
    expect(surface.score).toBe(3);
  });
});
