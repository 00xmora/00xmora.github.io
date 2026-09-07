import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// base: './' makes the build use relative asset paths, so it works whether
// this is deployed as a GitHub Pages user site (root) or a project site
// (a subpath like /repo-name/) without any extra configuration.
export default defineConfig({
  plugins: [react()],
  base: './',
})
