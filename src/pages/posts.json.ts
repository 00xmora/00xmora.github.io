/**
 * /posts.json — a machine-readable index of every writeup.
 * Consumed by the terminal's `posts <query>` command and the home page strip.
 * Generated at build time so it can never drift from the published posts.
 */
import { getPosts } from '../lib/blog';
import { isoDate } from '../lib/slug';

export async function GET() {
  const posts = await getPosts();

  const payload = posts.map((post) => ({
    title: post.title,
    url: post.url,
    date: isoDate(post.date),
    categories: post.categories,
    tags: post.tags,
    description: post.description,
  }));

  return new Response(JSON.stringify(payload, null, 2), {
    headers: { 'Content-Type': 'application/json; charset=utf-8' },
  });
}
