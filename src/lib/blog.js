/**
 * Shared blog listing helpers.
 * A single place that turns content-collection entries into the shape every
 * listing page needs, so the writeups index, tag pages, archive and the home
 * page can never disagree about a post's URL or metadata.
 *
 * @typedef {object} Post
 * @property {any}    entry
 * @property {string} slug
 * @property {string} url
 * @property {string} title
 * @property {string} description
 * @property {Date}   date
 * @property {string[]} categories
 * @property {string[]} tags
 * @property {string|undefined} image
 * @property {boolean} pinned
 */
import { getCollection } from 'astro:content';
import { postUrl, slugify, slugifyTag, toStringArray } from './slug.js';

export function slugifyTagName(name) {
  return slugifyTag(name);
}

/** @returns {Promise<Post[]>} */
export async function getPosts() {
  const entries = await getCollection('posts');

  const posts = entries.map((entry) => {
    const categories = toStringArray(entry.data.categories);
    const tags = toStringArray(entry.data.tags);
    const slug = slugify(entry.filePath ?? entry.id);

    return {
      entry,
      slug,
      url: postUrl(slug),
      title: entry.data.title,
      description: entry.data.description || entry.data.summary || '',
      date: entry.data.date,
      categories,
      tags,
      image: entry.data.image,
      pinned: Boolean(entry.data.pin),
    };
  });

  // Newest first; pinned posts float to the top of the listing.
  return posts.sort((a, b) => {
    if (a.pinned !== b.pinned) return a.pinned ? -1 : 1;
    return b.date.valueOf() - a.date.valueOf();
  });
}

/** Rough reading time from the raw markdown body. */
export function readingTime(body = '') {
  const words = body.trim().split(/\s+/).filter(Boolean).length;
  const minutes = Math.max(1, Math.round(words / 210));
  return `${minutes} min read`;
}

/**
 * Group posts into `{ label, slug, count }` buckets for tag/category pages.
 * @param {Post[]} postList
 * @param {'tags'|'categories'} key
 */
export function groupBy(postList, key) {
  const map = new Map();
  postList.forEach((p) => {
    p[key].forEach((v) => map.set(v, (map.get(v) || 0) + 1));
  });
  return [...map.entries()]
    .map(([label, count]) => ({ label, slug: slugifyTag(label), count }))
    .sort((a, b) => b.count - a.count || a.label.localeCompare(b.label));
}

/** Posts grouped by year, for the archive page. @param {Post[]} postList */
export function groupByYear(postList) {
  const map = new Map();
  postList.forEach((p) => {
    const year = p.date.getUTCFullYear();
    if (!map.has(year)) map.set(year, []);
    map.get(year).push(p);
  });
  return [...map.entries()]
    .map(([year, posts]) => ({ year, posts }))
    .sort((a, b) => b.year - a.year);
}

/** Site-wide totals, used in headers. @param {Post[]} postList */
export function stats(postList) {
  return {
    posts: postList.length,
    tags: new Set(postList.flatMap((p) => p.tags)).size,
    categories: new Set(postList.flatMap((p) => p.categories)).size,
  };
}
