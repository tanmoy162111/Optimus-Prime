import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',
    port: 3000,
    proxy: {
      '/health': { target: 'http://backend:8000', changeOrigin: true },
      '/directives': { target: 'http://backend:8000', changeOrigin: true },
      '/scope': { target: 'http://backend:8000', changeOrigin: true },
      '/gate': { target: 'http://backend:8000', changeOrigin: true },
      '/report': { target: 'http://backend:8000', changeOrigin: true },
      '/terminal': { target: 'http://backend:8000', changeOrigin: true },
      '/ws': {
        target: 'ws://backend:8000',
        ws: true,
        changeOrigin: true,
      },
      '/chat': {
        target: 'ws://backend:8000',
        ws: true,
        changeOrigin: true,
      },
    },
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test-setup.js'],
    passWithNoTests: true,
  },
})
