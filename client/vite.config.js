import { defineConfig } from 'vite';

// The web wallet. `npm run web:build` writes a static site to ../docs, which
// GitHub Pages can serve as-is. There is no server-side part.
export default defineConfig({
  root: 'web',
  base: './',
  build: {
    outDir: '../../docs',
    emptyOutDir: true,
    target: 'es2022',
    sourcemap: false,
  },
  server: { host: '127.0.0.1', port: 5173 },
  preview: { host: '127.0.0.1', port: 4173 },
});
