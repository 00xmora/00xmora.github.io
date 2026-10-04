/**
 * RSS feed at /feed.xml — the same path the old Chirpy blog published, so
 * existing subscribers keep working.
 */
import rss from '@astrojs/rss';
import { getPosts } from '../lib/blog';

export async function GET(context) {
  const posts = await getPosts();

  return rss({
    title: 'Omar Samy — Cybersecurity Blog & things',
    description:
      'Technical blog about cybersecurity, writeups, CTFs, and practical notes on web and mobile hacking, pentesting and more.',
    site: context.site ?? 'https://00xmora.github.io',
    xmlns: { atom: 'http://www.w3.org/2005/Atom' },
    customData: '<language>en</language>',
    items: posts.map((post) => ({
      title: post.title,
      description: post.description,
      link: post.url,
      pubDate: post.date,
      categories: [...post.categories, ...post.tags],
    })),
  });
}
