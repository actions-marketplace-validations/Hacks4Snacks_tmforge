/// <reference types="vitest/config" />
import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

// https://vite.dev/config/
export default defineConfig(({ mode }) => {
  // Base public path. Defaults to '/' (served by the API at its root, or a root/custom-domain site).
  // The GitHub Pages workflow sets VITE_BASE='/<repo>/' for a project-site subpath. loadEnv reads it
  // (from the shell or a .env file) without needing @types/node in this config.
  const env = loadEnv(mode, '.', 'VITE_');
  return {
    base: mode === 'vscode' ? './' : env.VITE_BASE ?? '/',
    publicDir: mode === 'vscode' ? false : 'public',
    define: mode === 'vscode' ? { 'process.env.NODE_ENV': JSON.stringify('production') } : undefined,
    plugins: [react()],
    build: mode === 'vscode' ? {
      outDir: '../ThreatModelForge.Vscode/media/studio',
      emptyOutDir: true,
      lib: { entry: 'src/vscode.tsx', formats: ['es'], fileName: 'studio', cssFileName: 'studio' },
      rolldownOptions: { output: { codeSplitting: false } },
    } : undefined,
    server: { port: 5199, open: true },
    // Vitest: jsdom DOM environment for React component tests. Test files live next to the code
    // they cover (src/**/*.test.ts[x]) and are excluded from the production tsc build. Globals are
    // off — tests import { describe, it, expect } from 'vitest' explicitly.
    test: {
      environment: 'jsdom',
      setupFiles: ['./src/test/setup.ts'],
      include: ['src/**/*.test.{ts,tsx}'],
      css: false,
      coverage: {
        provider: 'v8',
        include: ['src/**/*.{ts,tsx}'],
        // Test files, the app shell, and the generated API client types are not behaviour to cover.
        exclude: ['src/**/*.test.{ts,tsx}', 'src/main.tsx', 'src/dfd/engine/schema.d.ts', 'src/vite-env.d.ts'],
        // Floors, not targets: raise them as coverage improves, and never lower one without saying
        // why. They sit just under today's numbers so an unrelated change cannot trip them, while a
        // real regression still fails the run.
        thresholds: {
          statements: 63,
          branches: 51,
          functions: 57,
          lines: 64,
        },
      },
    },
  };
});
