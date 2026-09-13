import react from '@vitejs/plugin-react';
// defineConfig from vitest/config, not vite: it is the one that accepts `test`.
import { defineConfig } from 'vitest/config';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    // Proxy API and probe calls to the backend so the browser sees one origin during
    // development. That keeps the auth cookies first-party, exactly as in production
    // where Caddy fronts both (SEC-02, SEC-03).
    proxy: {
      '/api': { target: 'http://localhost:8000', changeOrigin: true },
      '/healthz': { target: 'http://localhost:8000', changeOrigin: true },
      '/readyz': { target: 'http://localhost:8000', changeOrigin: true },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
    target: 'es2022',
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    css: false,
  },
});
