import { defineCollection, z } from 'astro:content';
import { glob } from 'astro/loaders';

/**
 * Writeups live as plain CommonMark in `content/posts/`.
 * Filenames follow `YYYY-MM-DD-Title With Spaces.md`; the slug used in the URL
 * is derived from the filename (see src/lib/slug.ts) so the existing, indexed
 * URLs like /posts/Pickle-RCE-Exfiltrating-Secrets-via-Unsafe-Deserialization/
 * keep working unchanged.
 */
const posts = defineCollection({
  loader: glob({ pattern: '**/*.md', base: './content/posts' }),
  schema: z.object({
    title: z.string(),
    description: z.string().optional(),
    summary: z.string().optional(),
    date: z.coerce.date(),
    categories: z.union([z.string(), z.array(z.string())]).optional(),
    tags: z.union([z.string(), z.array(z.string())]).optional(),
    image: z.string().optional(),
    pin: z.coerce.boolean().optional(),
    read_time: z.union([z.string(), z.number()]).optional(),
    toc: z.coerce.boolean().optional(),
    comments: z.coerce.boolean().optional(),
  }),
});

export const collections = { posts };
