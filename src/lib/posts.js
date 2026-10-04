/**
 * Reads the index of blog writeups.
 *
 * `/posts.json` is generated at build time by Jekyll (blog/posts.json), so it
 * always matches what is actually published. When it is missing — local dev
 * with the blog not built, or an offline load — we fall back to the last known
 * list so the terminal and the home page never render empty.
 */

export const POST_INDEX_URL = '/posts.json';

/** Last known published writeups, newest first. Used as an offline fallback. */
export const FALLBACK_POSTS = [
  {
    title: 'Node.js Arbitrary File Upload to RCE – AppSec Master Challenge Writeup',
    url: '/posts/Node.js-Arbitrary-File-Upload-to-RCE-%E2%80%93-AppSec-Master-Challenge-Writeup/',
    date: '2025-08-03',
    categories: ['code-review'],
    tags: ['nodejs', 'file-upload', 'path-traversal', 'rce', 'challenge'],
    description:
      'Exploiting an insecure Node.js file upload endpoint with a path traversal payload to land an arbitrary file and escalate to remote code execution.',
  },
  {
    title: 'Pickle RCE: Exfiltrating Secrets via Unsafe Deserialization',
    url: '/posts/Pickle-RCE-Exfiltrating-Secrets-via-Unsafe-Deserialization/',
    date: '2025-07-31',
    categories: ['code-review'],
    tags: ['rce', 'pickle', 'deserialization', 'flask', 'webhook', 'appsecmaster'],
    description:
      'A Flask app deserializes user-supplied base64 state with pickle.loads(), handing out remote code execution. Building the payload and exfiltrating /tmp/masterkey.txt.',
  },
  {
    title: 'SpEL Injection Exploit – AppSec Master Challenge Writeup',
    url: '/posts/SpEL-Injection-Exploit-%E2%80%93-AppSec-Master-Challenge-Writeup/',
    date: '2025-07-31',
    categories: ['code-review'],
    tags: ['spel', 'java', 'rce', 'injection', 'challenge'],
    description:
      'Spring Expression Language injection in a Java service, abused to run commands on the server and read the masterkey file.',
  },
  {
    title: 'Code Review: Exploiting SSTI in Node.js Template Rendering',
    url: '/posts/Exploiting-SSTI-in-Node.js-Template-Rendering/',
    date: '2025-07-28',
    categories: ['code-review'],
    tags: ['ssti', 'nodejs', 'vm', 'security', 'appsecmaster'],
    description:
      'Auditing a custom Node.js template renderer to find a server-side template injection and break out of the vm sandbox.',
  },
  {
    title: 'Race Condition A Detailed Exploration',
    url: '/posts/Race-Condition-A-Detailed-Exploration/',
    date: '2025-06-16',
    categories: ['research'],
    tags: ['race-condition', 'security', 'multithreading', 'synchronization', 'web-security'],
    description:
      'Race condition classes, how they are exploited in practice, and the mitigation strategies that actually hold up.',
  },
  {
    title: 'Flag28Service AIDL Binding Walkthrough (Hextree Lab)',
    url: '/posts/Flag28Service-AIDL-Binding-Walkthrough-%28Hextree-Lab%29/',
    date: '2025-06-15',
    categories: ['android'],
    tags: ['android', 'aidl', 'binder', 'reverse engineering'],
    description:
      'Reverse engineering an exported Android AIDL-based bound Service from another app and exploiting the binding to reach the flag.',
  },
  {
    title: 'Hextree Labs - Flag27Service Messenger Vulnerability (Solution)',
    url: '/posts/Hextree-Labs-Flag27Service-Messenger-Vulnerability-%28Solution%29/',
    date: '2025-06-14',
    categories: ['android'],
    tags: ['android', 'ctf', 'hextree labs', 'messenger', 'ipc', 'reverse engineering'],
    description:
      'Exploiting an Android Service vulnerability involving Messenger IPC and state management to retrieve a hidden flag.',
  },
  {
    title: 'Exploiting Flag26Service – Android Messenger-Based Service (Hextree CTF)',
    url: '/posts/Exploiting-Flag26Service-%E2%80%93-Android-Messenger-Based-Service-%28Hextree-CTF%29/',
    date: '2025-06-09',
    categories: ['android'],
    tags: ['android', 'ipc', 'messenger', 'ctf', 'hextree'],
    description:
      'A bound Service exposes a Messenger IPC interface via onBind(). Enumerating it, sending crafted messages, and pulling the flag.',
  },
  {
    title: 'How I Tricked the System with Type Confusion and Became a System Admin (Briefly)',
    url: '/posts/How-I-Tricked-the-System-with-Type-Confusion-and-Became-a-System-Admin-%28Briefly%29/',
    date: '2025-03-24',
    categories: ['web'],
    tags: ['type confusion', 'access-control', 'api-security', 'bug-bounty'],
    description:
      'A type confusion bug allowed privilege escalation to a System Administrator role by tweaking a numeric value in an API request.',
  },
  {
    title: 'Path Traversal in File Upload via GraphQL API',
    url: '/posts/Path-Traversal-in-File-Upload-via-GraphQL-API/',
    date: '2025-03-11',
    categories: ['web'],
    tags: ['path-traversal', 'file-upload', 'graphql', 'gcp'],
    description:
      'A file upload endpoint accepted folder traversal sequences, enabling unauthorized file placement and abuse of signed Google Cloud Storage URLs.',
  },
  {
    title: 'Auth Token Theft via CORS Misconfiguration',
    url: '/posts/Auth-Token-Theft-via-CORS-Misconfiguration/',
    date: '2025-03-08',
    categories: ['web'],
    tags: ['cors', 'auth-token-theft', 'access-control', 'bug-bounty', 'web-security'],
    description:
      'A CORS misconfiguration with a wildcard-like origin match and Access-Control-Allow-Credentials allowed authentication tokens to be stolen.',
  },
  {
    title: 'Privilege Escalation via Chat Permissions Bypass',
    url: '/posts/Privilege-Escalation-via-Chat-Permissions-Bypass/',
    date: '2024-02-07',
    categories: ['web'],
    tags: ['privilege-escalation', 'access-control', 'api-security', 'bug-bounty'],
    description:
      'A real-world case where UI-level permission controls were not enforced at the API level, allowing message sending and user impersonation.',
  },
];

let cache = null;

/** Fetch the published post index, falling back to the bundled list. */
export async function loadPosts() {
  if (cache) return cache;

  try {
    const res = await fetch(POST_INDEX_URL, { cache: 'no-cache' });
    if (res.ok) {
      const data = await res.json();
      if (Array.isArray(data) && data.length) {
        cache = data;
        return cache;
      }
    }
  } catch {
    /* fall through to the bundled list */
  }

  cache = FALLBACK_POSTS;
  return cache;
}

export function formatDate(iso) {
  if (!iso) return '';
  const d = new Date(`${iso}T00:00:00Z`);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleDateString('en-GB', {
    day: 'numeric',
    month: 'short',
    year: 'numeric',
    timeZone: 'UTC',
  });
}

/** Naive but effective relevance ranking for the terminal's `posts` command. */
export function searchPosts(posts, query) {
  const q = String(query || '').trim().toLowerCase();
  if (!q) return posts;

  const terms = q.split(/\s+/).filter(Boolean);

  return posts
    .map((p) => {
      const title = p.title.toLowerCase();
      const tags = (p.tags || []).join(' ').toLowerCase();
      const cats = (p.categories || []).join(' ').toLowerCase();
      const desc = (p.description || '').toLowerCase();

      let score = 0;
      for (const t of terms) {
        if (title.includes(t)) score += 6;
        if (tags.includes(t)) score += 4;
        if (cats.includes(t)) score += 3;
        if (desc.includes(t)) score += 2;
      }
      return { post: p, score };
    })
    .filter((r) => r.score > 0)
    .sort((a, b) => b.score - a.score)
    .map((r) => r.post);
}
