// @ts-check
import { defineConfig } from 'astro/config';
import react from '@astrojs/react';
import sitemap from '@astrojs/sitemap';

export default defineConfig({
  site: 'https://00xmora.github.io',

  // Single static site: portfolio at the root, writeups at /posts/.
  // No base path — the writeups are served from the domain root exactly like
  // the pre-restructure blog was, so indexed URLs keep resolving.
  base: '/',

  integrations: [
    react(),
    sitemap({
      // The error page and the legacy redirect stubs must not enter the index.
      filter: (page) =>
        !page.includes('/404') && !page.includes('/blog/') && page !== 'https://00xmora.github.io/blog',
    }),
  ],

  /**
   * Legacy URL preservation.
   *
   * `/blog/` and `/blog/posts/<slug>/` are handled by real redirect pages in
   * src/pages/blog/ (so every old post URL redirects, not just a hardcoded
   * few). These entries cover the non-post routes that used to live under
   * /blog/. Destinations are the canonical /posts/ pages.
   */
  redirects: {
    '/blog/feed.xml': '/feed.xml',
    '/blog/page2': '/posts/',
    '/blog/page3': '/posts/',

    // Retired routes. Skills now lives in the terminal (`skills` / `certs`) and
    // on /about/; the writeups index and the blog listing are the same thing,
    // so both collapse into /posts/.
    '/skills': '/about/',
    '/skills/': '/about/',
    '/writeups': '/posts/',
    '/writeups/': '/posts/',
  },

  markdown: {
    // Shiki is built in — real syntax highlighting at build time, no client JS.
    shikiConfig: {
      themes: {
        dark: 'github-dark-default',
        light: 'github-light',
      },
      wrap: false,
    },
  },

  prefetch: {
    prefetchAll: false,
    defaultStrategy: 'hover',
  },

  build: {
    // Emit /posts/slug/index.html so every writeup lives at a directory URL
    // with a trailing slash — identical shape to the old Chirpy permalinks.
    format: 'directory',
    inlineStylesheets: 'auto',
  },

  compressHTML: true,
});
