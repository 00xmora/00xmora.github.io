# 00xmora.github.io

This repo builds **two sites from one repo** and deploys them together to
GitHub Pages:

- **`/`** — Omar Samy's portfolio (React + Vite), source in [`portfolio/`](portfolio)
- **`/blog/`** — the existing technical blog (Jekyll + Chirpy theme), source in [`blog/`](blog)

A single GitHub Actions workflow ([`.github/workflows/deploy.yml`](.github/workflows/deploy.yml))
builds both and deploys them as one site on every push to `main`:
`https://00xmora.github.io/` for the portfolio, `https://00xmora.github.io/blog/`
for the blog.

## ⚠️ Migrating your existing `00xmora.github.io` repo — read first

Your blog currently lives at the **root** of the `00xmora/00xmora.github.io`
repo. This restructuring moves that same content into a `blog/` subfolder
(with `baseurl: "/blog"` set in `blog/_config.yml`) and adds the portfolio
alongside it. Because this changes the repo layout significantly, do this
carefully:

1. **Back up first.** Your existing repo already has everything in git
   history, so nothing is lost — but it's worth keeping a local clone of
   the current state before you overwrite anything, just in case.

2. **Clone your real repo fresh** (a clean copy, not this download):
   ```bash
   git clone https://github.com/00xmora/00xmora.github.io.git
   cd 00xmora.github.io
   ```

3. **Delete everything except `.git`**, then copy in the contents of this
   package:
   ```bash
   find . -mindepth 1 -maxdepth 1 ! -name '.git' -exec rm -rf {} +
   # then copy every file/folder from this download into this directory,
   # so you end up with: portfolio/, blog/, .github/, .gitignore, .gitmodules, README.md
   ```
   The `blog/` folder here already contains your existing posts, theme
   config, and assets — copied as-is from your current repo, with only
   `_config.yml`'s `baseurl` changed to `"/blog"`.

4. **Re-link the theme's static-assets submodule** (its path changed from
   `assets/lib` to `blog/assets/lib`):
   ```bash
   git submodule deinit -f assets/lib 2>/dev/null || true
   git rm -f assets/lib 2>/dev/null || true
   git submodule add https://github.com/cotes2020/chirpy-static-assets.git blog/assets/lib
   ```
   (If `git submodule add` complains the path already exists from the copy
   step above, delete `blog/assets/lib` first, then run the command again.)

5. **Commit and push:**
   ```bash
   git add -A
   git commit -m "Restructure: portfolio at root, blog moved to /blog"
   git push
   ```

6. **In GitHub → repo Settings → Pages**, confirm **Source** is set to
   **GitHub Actions** (it may already be, from the blog's previous Chirpy
   workflow). Then check the **Actions** tab — the new combined workflow
   will run automatically and deploy both sites together.

7. **Google Search Console**: your site-verification file
   (`googlefb1f3b853a05bcd1.html`) is now served from the portfolio at
   `portfolio/public/`, so it still resolves at
   `https://00xmora.github.io/googlefb1f3b853a05bcd1.html` — no re-verification
   should be needed. Worth double-checking in Search Console after deploy
   either way.

## A note on limits here

I restructured and reconfigured everything (moved your blog into `blog/`,
updated its `baseurl`, rewired the submodule path, wrote the combined
workflow) but **could not build or preview the Jekyll blog myself** in this
environment — it doesn't have access to RubyGems. The config changes are
standard Jekyll/Chirpy practice (this is exactly what `baseurl` is for), but
it's worth watching the first Actions run closely and fixing anything that
comes up. If the build fails, paste me the Actions log and I'll help debug it.

## Local development

**Portfolio:**
```bash
cd portfolio
npm install
npm run dev
```

**Blog** (requires Ruby/Bundler):
```bash
cd blog
bundle install
bundle exec jekyll serve --baseurl ""
```
(Serving locally with an empty `--baseurl` override is easiest so links
resolve at `http://localhost:4000` instead of `http://localhost:4000/blog`.)

## Editing content

- Portfolio text/pages: see `portfolio/src/components/` and `portfolio/src/pages/`
- Blog posts: add markdown files to `blog/_posts/`, same as before
- Site-wide colors/fonts for the portfolio: `portfolio/src/index.css`
