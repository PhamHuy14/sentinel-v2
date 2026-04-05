import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import electron from 'vite-plugin-electron';
import renderer from 'vite-plugin-electron-renderer';

export default defineConfig({
  plugins: [
    react(),
    electron([
      {
        entry: 'electron/main.js',
      },
      {
        entry: 'electron/preload.js',
        onstart(options) {
          // Restart renderer khi preload thay đổi
          options.reload();
        },
      },
    ]),
    renderer(),
  ],
  base: './',
  build: {
    outDir: 'dist-electron/renderer',
    emptyOutDir: true,
  },
});
