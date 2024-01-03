// @ts-nocheck
import { resolve } from "node:path";
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  build: {
    rollupOptions: {
      input: {
        main: resolve(__dirname, "src/index.html"),
        signup: resolve(__dirname, "src/auth/signup.html"),
        login: resolve(__dirname, "src/auth/login.html"),
      },
    },
    outDir: "../dist",
  },
  publicDir: "../public",
  root: "src",
})
