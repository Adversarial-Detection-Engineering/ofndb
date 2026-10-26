import { defineConfig } from 'astro/config';

// GitHub Pages project sites live under /<repo>/: CI sets BASE_PATH and SITE_URL.
export default defineConfig({
  site: process.env.SITE_URL || 'http://localhost:4321',
  base: process.env.BASE_PATH || '/',
  trailingSlash: 'always',
  build: { format: 'directory' },
});
