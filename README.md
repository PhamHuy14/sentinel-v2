# SENTINEL v2

SENTINEL v2 is an Electron + React desktop app for OWASP-focused security scanning, findings review, checklist management, and offline security assistance.

## Requirements

- Node.js `20.x`
- npm `10.x`
- Windows is the primary packaging target

Use `.nvmrc` if you manage Node with `nvm`:

```bash
nvm use
```

## Getting Started

```bash
npm install
npm run dev
```

## Standard Commands

```bash
npm run typecheck
npm run lint
npm test
npm run build
npm run dist
```

## Build Flow

Development flow:

- `npm run dev` starts Vite for the renderer and `vite-plugin-electron` wires Electron to the dev server.
- In development, `electron/main.js` loads `process.env.VITE_DEV_SERVER_URL`.

Production build flow:

- `npm run build` first runs `typecheck`, then runs `vite build`.
- Vite builds the renderer into `dist-electron/renderer/`.
- `vite-plugin-electron` also builds Electron entry files such as `dist-electron/main.js`.
- In production, `electron/main.js` loads `dist-electron/renderer/index.html`.

Packaging flow:

- `npm run dist` builds the app, then packages a Windows portable build via `electron-builder`.

## Project Structure

```text
src/       React renderer, stores, UI, AI assistant logic
electron/  Electron main and preload processes
engine/    Scanning engine and report logic
public/    Static assets copied into the renderer build
```

## Source Of Truth

- Renderer source lives in `src/**/*.ts` and `src/**/*.tsx`.
- Do not commit generated JavaScript siblings inside `src/`.
- Build output belongs in `dist-electron/` and should not be edited manually.

## Path Aliases

The repo supports:

- `@/` -> `src/`
- `@engine/` -> `engine/`

Prefer relative imports for nearby files and aliases for shared cross-folder imports.

## Platform Notes

- Development can be done on any environment supported by Node/Electron, but the current packaging command targets Windows portable output.
- If you add platform-specific behavior, document it in the same PR.

## Contributor Rules

See `CONTRIBUTING.md` for naming, file placement, and repo hygiene conventions.
