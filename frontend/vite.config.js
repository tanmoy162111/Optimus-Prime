import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',
    port: 3000,
    proxy: {
      '/health': 'http://localhost:8000',
      '/directives': 'http://localhost:8000',
      '/scope': 'http://localhost:8000',
      '/gate': 'http://localhost:8000',
      '/ws': {
        target: 'ws://localhost:8000',
        ws: true,
      },
      '/chat': {
        target: 'ws://localhost:8000',
        ws: true,
      },
    },
  },
})
