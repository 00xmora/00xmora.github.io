/**
 * Slug handling for writeups.
 *
 * The live blog has been served under different URL shapes over time:
 *
 *   1. /posts/<Title-With-Hyphens>/                          (original, indexed by Google)
 *   2. /blog/posts/<Title-With-Hyphens>/                     (after the blog moved under /blog)
 *   3. /blog/posts/<Title-With-%CE%93%C3%87%C3%B4-Hyphens>/  (mojibake en-dashes)
 *
 * The old theme derived the slug from the front-matter title with whitespace
 * collapsed to hyphens. We reproduce that exactly from the source filename,
 * after normalising the three filenames whose UTF-8 en-dashes were mangled on
 * an earlier commit — so generated URLs are clean again and identical in shape
 * to (1), which is what search engines actually have indexed.
 */

/** '–' (en dash) as it appears after being mangled through Latin-1/UTF-8. */
const MOJIBAKE = ['\u0393\u00c7\u00f4', '\u00e2\u0080\u0093', '\u2013'];

/** Strip a leading `YYYY-MM-DD-` date prefix and the `.md` extension. */
function baseName(filePathOrId) {
  const file = String(filePathOrId).split(/[/\\]/).pop() || '';
  return file
    .replace(/\.mdx?$/i, '')
    .replace(/^\d{4}-\d{2}-\d{2}-/, '')
    .trim();
}

/**
 * URL slug: collapse any whitespace run to a single hyphen and trim, but
 * preserve letter case and characters such as `.` and `()`.
 */
export function slugify(name) {
  let value = baseName(name);
  for (const bad of MOJIBAKE) {
    value = value.split(bad).join('');
  }
  return value
    .replace(/\s+/g, '-')
    .replace(/-{2,}/g, '-')
    .replace(/^-|-$/g, '');
}

/** Canonical published URL for a writeup. */
export function postUrl(slug) {
  return `/posts/${slug}/`;
}

/** URL-safe form of a tag/category name. */
export function slugifyTag(name) {
  return String(name)
    .trim()
    .toLowerCase()
    .replace(/[^\w\s.-]/g, '')
    .replace(/\s+/g, '-')
    .replace(/-{2,}/g, '-')
    .replace(/^-|-$/g, '');
}

/** The live (Chirpy) URLs for the three mojibake-titled posts. */
export const LEGACY_MOJIBAKE_URLS = [
  '/blog/posts/Exploiting-Flag26Service-%CE%93%C3%87%C3%B4-Android-Messenger-Based-Service-%28Hextree-CTF%29/',
  '/blog/posts/SpEL-Injection-Exploit-%CE%93%C3%87%C3%B4-AppSec-Master-Challenge-Writeup/',
  '/blog/posts/Node.js-Arbitrary-File-Upload-to-RCE-%CE%93%C3%87%C3%B4-AppSec-Master-Challenge-Writeup/',
];

export function formatDate(date) {
  const d = date instanceof Date ? date : new Date(date);
  if (Number.isNaN(d.getTime())) return '';
  return d.toLocaleDateString('en-GB', {
    day: 'numeric',
    month: 'short',
    year: 'numeric',
    timeZone: 'UTC',
  });
}

export function isoDate(date) {
  const d = date instanceof Date ? date : new Date(date);
  if (Number.isNaN(d.getTime())) return '';
  return d.toISOString().slice(0, 10);
}

/** Normalise `categories` / `tags`, which may be a string or an array. */
export function toStringArray(value) {
  if (!value) return [];
  if (Array.isArray(value)) return value.map((v) => String(v).trim()).filter(Boolean);
  // YAML lists written as "a, b, c" on one line are common in this blog.
  return String(value)
    .split(',')
    .map((v) => v.trim())
    .filter(Boolean);
}
