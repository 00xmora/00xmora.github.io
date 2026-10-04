# 00xmora.github.io

Omar Samy's portfolio and technical writeups — **one Astro site, one build, one deploy**.

- **`/`** — the portfolio (hero, about, services, experience, skills, contact)
- **`/writeups/`** — all writeups with a live filter
- **`/posts/<slug>/`** — the articles themselves
- **`/tags/`, `/categories/`, `/archives/`** — taxonomy and archive
- **`/feed.xml`**, **`/posts.json`**, **`/sitemap-index.xml`** — generated feeds and indexes
- **`/blog/*`** — redirect stubs preserving every URL the old Jekyll blog published

## Stack

| Concern | Choice |
|---|---|
| Framework | [Astro](https://astro.build) 5, fully static output |
| Interactive bits | React 19, used only for the terminal (one island) |
| Syntax highlighting | Shiki, at build time — no client-side highlighter |
| Styling | Plain CSS with custom properties. No Tailwind, no CSS-in-JS |
| Content | Markdown in `content/posts/` with Zod-validated front matter |
| Hosting | GitHub Pages via GitHub Actions |

There is **no Ruby, no Jekyll, no Bundler** anywhere in this project. `npm run build` produces the entire site into `dist/`.

## Commands

```bash
npm install
npm run dev      # local dev server
npm run build    # full static build into dist/
npm run preview  # serve the built output
```

## Writing a post

Create `content/posts/YYYY-MM-DD-Your Title Here.md`:

```markdown
---
title: Your Title Here
date: 2025-08-03
categories: web
tags:
  - rce
  - file-upload
description: One or two sentences used for the listing, SEO and the RSS feed.
image: https://example.com/cover.png
---

Body in plain CommonMark. Code fences get highlighted automatically.
```

The filename drives the URL. `2025-08-03-Node.js Arbitrary File Upload.md`
becomes `/posts/Node.js-Arbitrary-File-Upload/`.

> **Do not add a `date` prefix to the title in front matter** and do not change
> an existing filename unless you also add a redirect — the URL is the filename,
> and these URLs are indexed by search engines.

## How URLs stay stable

This matters more than it looks. The blog has been served under three different
URL shapes over the years:

1. `/posts/<Title-With-Hyphens>/` — the original, and what Google indexed
2. `/blog/posts/<Title-With-Hyphens>/` — after the blog moved under `/blog/`
3. `/blog/posts/<Title-With-%CE%93%C3%87%C3%B4-...>/` — three posts whose
   en-dashes were mangled in an earlier commit

The current build makes shape **(1)** canonical again, exactly as it was before,
and `src/pages/blog/` emits redirect stubs so shapes (2) and (3) still resolve.
`src/lib/slug.js` reproduces the original slug rule and strips the mojibake, so
the generated URLs are clean.

If you ever rename a post file, add an entry to `redirects` in
`astro.config.mjs` so the old URL keeps working.

## Project layout

```
content/posts/          writeup markdown (the only files you normally edit)
public/                 static assets served as-is (images, robots.txt, .nojekyll)
src/
  components/           Nav, Footer, Hero, PostCard + Terminal.jsx (React island)
  data/profile.js       single source of truth for bio, skills, roles, links
  layouts/BaseLayout    <head>, SEO/OG meta, theme bootstrap, nav + footer
  lib/
    blog.js             content-collection → post objects, grouping, stats
    slug.js             slug rules + legacy URL handling
    posts.js            terminal's post index loader with offline fallback
  pages/                one file per route
  styles/               global tokens + per-surface CSS
astro.config.mjs        site URL, integrations, redirects, markdown config
```

## Theming

Dark is the default. The palette is a slate-blue system:

| Token | Value | Role |
|---|---|---|
| `--bg` | `#0B1120` | primary background |
| `--surface` | `#151F32` | cards / secondary background |
| `--accent` | `#3B82F6` | primary accent |
| `--accent-hover` | `#60A5FA` | accent hover |
| `--text` | `#F8FAFC` | primary text |
| `--text-dim` | `#94A3B8` | secondary text |
| `--border` | `#263449` | borders / hairlines |

Everything else is a derived step that fills the gaps between those roles
(`--bg-top`, `--surface-2`, `--border-strong`, `--accent-ink`, …). Two deliberate
departures from a literal reading of that spec:

- **Buttons never fill with `#3B82F6`.** White on it is 3.68:1 — below AA for
  14px text — so button gradients run `#1B42B8 → #2563EB` (8.3:1 → 5.2:1).
  `#3B82F6` stays the accent for text, icons and focus, where it hits 5.12:1.
- **`#263449` is used for hairlines *inside* a surface, not as the card
  outline.** At 1.5:1 against the background it is invisible as a boundary, so
  cards are outlined with a gradient ring built from `#3B82F6`/`#60A5FA`, which
  composites to 3.9:1 and 5.4:1 — visible without introducing any colour that
  isn't already in the palette.

Contrast summary: primary text 18:1, secondary text 7.3:1, accent text 5.1:1,
button text 5.2:1 — all AA or better.

Resolution order at load: `?theme=light` / `?theme=dark` in the URL → stored
choice in `localStorage` → OS `prefers-color-scheme` → dark. Everything reads
from CSS custom properties in `src/styles/global.css`, so changing the palette
means editing that one block. The terminal stays pure black in **both** themes,
the way a real terminal window does — those tokens live in `:root`, not in a
theme block.

## The terminal

`src/components/Terminal.jsx` is the only hydrated React component on the site.
It answers `help`, `whoami`, `about`, `skills`, `experience`, `certs`,
`services`, `posts <query>`, `contact`, `social`, `resume`, `status`, `theme`,
`sudo hire-me`, `cat`, `echo`, `date`, `pwd`, `ls`, and `clear`. Output for the
`posts` command is backed by `/posts.json`, generated at build time from the
content collection, so it can never list a post that does not exist.

**The toolkit lives here.** There is no Skills page: `skills` lists the groups
and `certs` lists certifications plus education. The nav is deliberately short
(About / Services / Experience / Blog) and `/skills/` redirects to `/about/`.

## Deploy

`git push` to `main`. `.github/workflows/deploy.yml` installs, runs
`npm run build`, and publishes `dist/` to GitHub Pages. No other build steps,
no submodules, no Ruby toolchain.
