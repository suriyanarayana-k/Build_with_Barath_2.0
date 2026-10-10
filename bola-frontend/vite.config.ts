import react from '@vitejs/plugin-react'
import { defineConfig, loadEnv } from 'vite'
import { fileURLToPath } from 'node:url'
import { resolve } from 'node:path'

// https://vite.dev/config/
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  return {
    root: fileURLToPath(new URL('.', import.meta.url)),
    plugins: [react()],
    resolve: { dedupe: ['react', 'react-dom'] },
    build: { outDir: resolve(process.cwd(), 'dist'), emptyOutDir: true },
    server: { proxy: { '/api': {
      target: env.BACKEND_PROXY_TARGET || 'http://127.0.0.1:8000',
      changeOrigin: true,
      rewrite: (path: string) => path.replace(/^\/api/, ''),
    } } },
  };
})
