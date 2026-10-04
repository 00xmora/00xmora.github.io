import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  certifications,
  experience,
  profile,
  services,
  skillGroups,
} from '../data/profile.js';
import { loadPosts, searchPosts } from '../lib/posts.js';
// Styles live in src/styles/terminal.css and are imported once by BaseLayout.

const PS1 = 'omar@00xmora';
const HOST = 'portfolio';

const BANNER = `  ___  __  __    _    ____     ____    _    __  __ __   __
 / _ \\|  \\/  |  / \\  |  _ \\   / ___|  / \\  |  \\/  |\\ \\ / /
| | | | |\\/| | / _ \\ | |_) |  \\___ \\ / _ \\ | |\\/| | \\ V /
| |_| | |  | |/ ___ \\|  _ <    ___) / ___ \\| |  | |  | |
 \\___/|_|  |_/_/   \\_\\_| \\_\\  |____/_/   \\_\\_|  |_|  |_|`;

let uid = 0;
const nextId = () => {
  uid += 1;
  return `l${uid}`;
};

const line = (text, type = 'out', extra = {}) => ({ id: nextId(), text, type, ...extra });

/* ------------------------------------------------------------------ *
 * Command registry
 * Each handler returns an array of line objects.
 * ------------------------------------------------------------------ */
function buildCommands() {
  const help = () => [
    line('available commands', 'head'),
    line(''),
    line('  whoami          who I am, in one paragraph', 'dim'),
    line('  about           the longer version', 'dim'),
    line('  skills          toolkit by area', 'dim'),
    line('  experience      roles and what I did there', 'dim'),
    line('  certs           certifications + education', 'dim'),
    line('  services        what I do for clients', 'dim'),
    line('  posts [query]   search my writeups  (e.g. posts rce)', 'dim'),
    line('  contact         how to reach me', 'dim'),
    line('  social          links off-site', 'dim'),
    line('  resume          download-ready summary', 'dim'),
    line('  status          current availability', 'dim'),
    line('  theme           toggle dark / light', 'dim'),
    line('  clear           wipe the buffer', 'dim'),
    line('  help            this list', 'dim'),
    line(''),
    line('  try: posts pickle   |   sudo hire-me   |   cat secrets.txt', 'accent'),
  ];

  const whoami = () => [
    line(`${profile.name} — ${profile.role}`, 'accent'),
    line(`${profile.location} · ${profile.remote}`),
    line(''),
    line(profile.bio),
    line(''),
    line(
      `> deep-dive:  about   |   skills   |   experience   |   posts`,
      'dim',
    ),
  ];

  const about = () => [
    line('about', 'head'),
    line(''),
    line(
      "I'm a cybersecurity professional working as a Presales Engineer, helping organizations strengthen their security posture and adopt modern application security practices. That covers technical consultations, solution design, product demos and PoCs, and — once a customer decides to move forward — the hands-on implementation that gets AppSec tooling actually running in their environment.",
    ),
    line(''),
    line(
      'Earlier time on the offensive side — penetration testing, vulnerability analysis, and SOC exposure — is what grounds these conversations in how systems actually get compromised, not just how a datasheet reads.',
    ),
    line(''),
    line(`> full page: /about`, 'dim'),
  ];

  const skills = () => {
    const out = [line('toolkit', 'head'), line('')];
    skillGroups.forEach((g) => {
      out.push(line(`▸ ${g.title}`, 'accent'));
      out.push(line(`  ${g.items.join(' · ')}`, 'dim'));
      out.push(line(''));
    });
    out.push(line('> full page: /about/', 'dim'));
    return out;
  };

  const exp = () => {
    const out = [line('experience', 'head'), line('')];
    experience.forEach((r) => {
      out.push(line(`▸ ${r.title}`, 'accent'));
      out.push(line(`  ${r.period} · ${r.org}`, 'dim'));
      r.points.forEach((p) => out.push(line(`  • ${p}`)));
      out.push(line(''));
    });
    out.push(line('> full page: /experience', 'dim'));
    return out;
  };

  const certs = () => {
    const out = [line('certifications', 'head'), line('')];
    certifications.forEach((c) => {
      out.push(line(`✔ ${c.name}`, 'ok'));
      out.push(line(`  ${c.body}`, 'dim'));
    });
    out.push(line(''));
    out.push(line(`🎓 ${profile.education}`, 'accent'));
    return out;
  };

  const svc = () => {
    const out = [line('services', 'head'), line('')];
    services.forEach((s) => {
      out.push(line(`[${s.tag}] ${s.title}`, 'accent'));
      out.push(line(`      ${s.body}`, 'dim'));
    });
    out.push(line(''));
    out.push(line('> scoping a PoC?  type: contact', 'dim'));
    return out;
  };

  const contact = () => [
    line('contact', 'head'),
    line(''),
    { ...line(`  email      ${profile.email}`), extra: { href: `mailto:${profile.email}` } },
    { ...line(`  calendly   calendly.com/00xmora`), extra: { href: profile.calendly, external: true } },
    { ...line(`  linkedin   in/00xmora`), extra: { href: profile.linkedin, external: true } },
    { ...line(`  github     github.com/00xmora`), extra: { href: profile.github, external: true } },
    { ...line(`  twitter    @00xmora`), extra: { href: profile.twitter, external: true } },
    line(''),
    line('> or use the contact page: /contact', 'dim'),
  ];

  const social = () => [
    line('elsewhere', 'head'),
    line(''),
    { ...line('  github    github.com/00xmora'), extra: { href: profile.github, external: true } },
    { ...line('  x         twitter.com/00xmora'), extra: { href: profile.twitter, external: true } },
    { ...line('  linkedin  linkedin.com/in/00xmora'), extra: { href: profile.linkedin, external: true } },
    { ...line('  facebook  facebook.com/00xmora'), extra: { href: profile.facebook, external: true } },
  ];

  const resume = () => [
    line('summary', 'head'),
    line(''),
    line(`  ${profile.name}`),
    line(`  ${profile.role}`, 'accent'),
    line(`  ${profile.location} · ${profile.remote}`),
    line(''),
    line('  FOCUS      AppSec tooling presales · DevSecOps · secure SDLC', 'dim'),
    line('  CURRENT    Prosoft — Cybersecurity Engineer | Presales Engineer', 'dim'),
    line('  PRIOR      Security Meter — Offensive Security Engineer (Intern)', 'dim'),
    line('  CERTS      CAP · CNSP · eJPTv1 · AWS Cloud Foundations', 'dim'),
    line('  DEGREE     ' + profile.education, 'dim'),
    line(''),
    line(`  → request the full CV at ${profile.email}`, 'accent'),
  ];

  const status = () => [
    line('status', 'head'),
    line(''),
    line(`  availability   ${profile.availability}`, 'ok'),
    line(`  location       ${profile.location}`, 'dim'),
    line(`  timezone       EET (UTC+2)`, 'dim'),
    line(`  response       usually within a day`, 'dim'),
  ];

  const posts = async (query) => {
    const all = await loadPosts();

    if (!all.length) {
      return [line('no posts index found — try /posts/ directly', 'warn')];
    }

    const results = query ? searchPosts(all, query) : all;

    if (!results.length) {
      return [
        line(`no writeups matched “${query}”`, 'warn'),
        line(''),
        line('try: posts rce | posts android | posts pickle | posts graphql', 'dim'),
      ];
    }

    const shown = results.slice(0, 8);
    const out = [
      line(
        query
          ? `${results.length} match${results.length === 1 ? '' : 'es'} for “${query}”`
          : `${all.length} writeups, newest first`,
        'head',
      ),
      line(''),
    ];

    shown.forEach((p) => out.push(line(p.title, 'post', { post: p })));

    if (results.length > shown.length) {
      out.push(line(''));
      out.push(line(`… and ${results.length - shown.length} more — browse /posts/`, 'dim'));
    }

    if (!query) {
      out.push(line(''));
      out.push(line('search a topic:  posts <keyword>', 'dim'));
    }

    return out;
  };

  const sudo = (args) => {
    const cmd = args.join(' ').trim().toLowerCase();
    if (cmd === 'hire-me' || cmd === 'hire me' || cmd === 'hire_me') {
      return [
        line('[sudo] password for visitor: ********', 'dim'),
        line(''),
        line('permission granted. escalating…', 'ok'),
        line(''),
        line("  Nice try — but you don't need root for this one.", 'accent'),
        line(`  Just email ${profile.email} and we'll talk.`, 'dim'),
      ];
    }
    if (cmd === 'rm -rf /' || cmd === 'rm -rf / ') {
      return [
        line('rm: it is not wise to delete the portfolio you are standing on.', 'err'),
        line('aborted. (nice instinct though — very offensive-security of you.)', 'dim'),
      ];
    }
    return [
      line(`[sudo] password for visitor:`, 'dim'),
      line(`${profile.handle} is not in the sudoers file. This incident has been reported.`, 'err'),
      line('…reported to: nobody. Try `sudo hire-me`.', 'dim'),
    ];
  };

  const cat = (args) => {
    const f = (args[0] || '').toLowerCase();
    if (f === 'secrets.txt') {
      return [
        line('cat: secrets.txt: Permission denied', 'err'),
        line('(yes, I checked for hardcoded credentials. that is the whole job.)', 'dim'),
      ];
    }
    if (f === 'about.md') return about();
    if (f === 'resume.txt' || f === 'cv.txt') return resume();
    return [line(`cat: ${args[0] || ''}: No such file or directory`, 'err')];
  };

  const echo = (args) => [line(args.join(' '))];

  const ok = (msg) => [{ ...line(msg, 'ok'), action: 'noop' }];

  return {
    help: { run: help, desc: 'list every command' },
    '?': { run: help, desc: 'alias for help' },
    whoami: { run: whoami, desc: 'who I am' },
    about: { run: about, desc: 'the longer story' },
    skills: { run: skills, desc: 'toolkit by area' },
    experience: { run: exp, desc: 'roles and impact' },
    exp: { run: exp, desc: 'alias for experience' },
    certs: { run: certs, desc: 'certifications' },
    certifications: { run: certs, desc: 'alias for certs' },
    services: { run: svc, desc: 'client-facing work' },
    posts: { run: posts, desc: 'search writeups' },
    writeups: { run: posts, desc: 'alias for posts' },
    blog: { run: posts, desc: 'alias for posts' },
    contact: { run: contact, desc: 'how to reach me' },
    social: { run: social, desc: 'off-site links' },
    resume: { run: resume, desc: 'summary block' },
    cv: { run: resume, desc: 'alias for resume' },
    status: { run: status, desc: 'availability' },
    sudo: { run: sudo, desc: 'try `sudo hire-me`' },
    cat: { run: cat, desc: 'cat <file>' },
    echo: { run: echo, desc: 'echo <text>' },
    date: { run: () => [line(new Date().toString())], desc: 'current time' },
    pwd: { run: () => [line('/home/omar/portfolio')], desc: 'print working directory' },
    ls: {
      run: () => [line('about  skills  experience  certs  services  posts  contact')],
      desc: 'list sections',
    },
    clear: { run: () => [], special: 'clear', desc: 'clear the screen' },
    theme: { run: () => [line('resolving theme…', 'dim')], special: 'theme', desc: 'toggle theme' },
  };
}

export default function Terminal({ sectionTag = 'Interactive', heading = 'Ask me anything' }) {
  const commands = useMemo(buildCommands, []);
  const [lines, setLines] = useState([]);
  const [input, setInput] = useState('');
  const [busy, setBusy] = useState(false);
  const [history, setHistory] = useState([]);
  const [histIndex, setHistIndex] = useState(-1);
  const [booted, setBooted] = useState(false);

  const bodyRef = useRef(null);
  const inputRef = useRef(null);
  const timers = useRef([]);
  const mounted = useRef(true);

  const names = useMemo(() => Object.keys(commands).sort(), [commands]);

  const scrollDown = useCallback(() => {
    const el = bodyRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, []);

  useEffect(() => {
    scrollDown();
  }, [lines, scrollDown]);

  // Boot sequence.
  useEffect(() => {
    mounted.current = true;
    const seq = [
      { d: 0, l: line('initialising portfolio shell v2.0 …', 'dim') },
      { d: 220, l: line('loading profile ..................... ok', 'dim') },
      { d: 400, l: line('loading writeup index ............... ok', 'dim') },
      { d: 580, l: { ...line(BANNER, 'ascii'), type: 'ascii' } },
      { d: 600, l: line('') },
      {
        d: 640,
        l: line(
          `Welcome. I'm ${profile.name.split(' ')[0]} — ${profile.role}.`,
          'accent',
        ),
      },
      { d: 700, l: line('Type `help` to see what I can answer, or click a suggestion below.', 'dim') },
      { d: 760, l: line('') },
    ];

    seq.forEach(({ d, l }) => {
      const t = setTimeout(() => {
        if (mounted.current) setLines((prev) => [...prev, l]);
      }, d);
      timers.current.push(t);
    });

    const bt = setTimeout(() => mounted.current && setBooted(true), 800);
    timers.current.push(bt);

    return () => {
      mounted.current = false;
      timers.current.forEach(clearTimeout);
      timers.current = [];
    };
  }, []);

  const pushLines = useCallback((items) => {
    setLines((prev) => [...prev, ...items]);
  }, []);

  const runCommand = useCallback(
    async (raw) => {
      const value = raw.trim();
      if (!value) return;

      setLines((prev) => [
        ...prev,
        { ...line(value, 'cmd'), type: 'cmd', prompt: true, id: nextId() },
      ]);
      setHistory((h) => (h[h.length - 1] === value ? h : [...h, value]));
      setHistIndex(-1);
      setInput('');

      const [name, ...args] = value.split(/\s+/);
      const entry = commands[name.toLowerCase()];

      if (!entry) {
        pushLines([
          line(`command not found: ${name}`, 'err'),
          line(`try \`help\` — or \`posts ${name}\` if you were looking for a writeup`, 'dim'),
        ]);
        return;
      }

      if (entry.special === 'clear') {
        setLines([]);
        return;
      }

      if (entry.special === 'theme') {
        // BaseLayout.astro owns the theme; it listens for this event so the
        // nav toggle and this command can never disagree about the state.
        const current = document.documentElement.getAttribute('data-theme');
        const nextTheme = current === 'light' ? 'dark' : 'light';
        document.dispatchEvent(new CustomEvent('os:set-theme', { detail: nextTheme }));
        pushLines([line(`theme → ${nextTheme}`, 'ok')]);
        return;
      }

      setBusy(true);
      try {
        const result = await entry.run(args);
        pushLines(result);
      } catch {
        pushLines([line('something went wrong running that command', 'err')]);
      } finally {
        setBusy(false);
        if (mounted.current) inputRef.current?.focus();
      }
    },
    [commands, pushLines],
  );

  const onKeyDown = (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      if (!busy) runCommand(input);
      return;
    }

    if (e.key === 'Tab') {
      e.preventDefault();
      const [first, ...rest] = input.split(/\s+/);

      if (!rest.length && first) {
        const matches = names.filter((n) => n.startsWith(first.toLowerCase()));
        if (matches.length === 1) setInput(`${matches[0]} `);
        else if (matches.length > 1) pushLines([line(matches.join('   '), 'dim')]);
      }
      return;
    }

    if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (!history.length) return;
      const idx = histIndex === -1 ? history.length - 1 : Math.max(0, histIndex - 1);
      setHistIndex(idx);
      setInput(history[idx]);
      return;
    }

    if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (histIndex === -1) return;
      const idx = histIndex + 1;
      if (idx >= history.length) {
        setHistIndex(-1);
        setInput('');
      } else {
        setHistIndex(idx);
        setInput(history[idx]);
      }
      return;
    }

    if (e.key === 'l' && e.ctrlKey) {
      e.preventDefault();
      setLines([]);
    }
  };

  const run = (cmd) => {
    if (busy) return;
    inputRef.current?.focus();
    runCommand(cmd);
  };

  const suggestions = ['help', 'whoami', 'skills', 'experience', 'posts', 'posts rce', 'certs', 'contact'];

  return (
    <section id="terminal" className="term" aria-labelledby="terminal-heading">
      <div className="wrap">
        <div className="term__head">
          <div className="term__intro">
            <div className="section-tag">
              <span className="dash" aria-hidden="true" />
              {sectionTag}
            </div>
            <h2 className="term__heading" id="terminal-heading">
              {heading}
            </h2>
            <p className="term__sub">
              This is a working shell, not a screenshot. Ask about my background, search the
              writeups by keyword, or just poke around — every answer is served from the site
              itself, with no backend and nothing to sign up for.
            </p>
          </div>
          <p className="term__hint mono">
            <kbd>↑</kbd> <kbd>↓</kbd> history · <kbd>Tab</kbd> complete · <kbd>Ctrl</kbd>+
            <kbd>L</kbd> clear
          </p>
        </div>

        <div className="term__window">
          <span className="term__focus-note">click to focus · type away</span>

          <div className="term__bar">
            <span className="term__dots" aria-hidden="true">
              <i />
              <i />
              <i />
            </span>
            <span className="term__title">
              {PS1}: ~/{HOST}
            </span>
            <span className="term__badge">interactive</span>
          </div>

          <div
            className="term__body"
            ref={bodyRef}
            role="log"
            aria-live="polite"
            aria-label="Terminal output"
            onClick={() => inputRef.current?.focus()}
          >
            {lines.map((l) => (
              <TermLine key={l.id} line={l} onRun={run} />
            ))}

            {booted && (
              <div className="term__chips">
                {suggestions.map((s) => (
                  <button type="button" className="term__chip" key={s} onClick={() => run(s)}>
                    {s}
                  </button>
                ))}
              </div>
            )}
          </div>

          <div className="term__input-row" onClick={() => inputRef.current?.focus()}>
            <span className="term__ps1" aria-hidden="true">
              {PS1}
            </span>
            <span className="term__ps2" aria-hidden="true">
              ~/{HOST} $
            </span>
            <input
              ref={inputRef}
              className="term__input"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={onKeyDown}
              placeholder={busy ? 'working…' : 'type a command, then Enter'}
              aria-label="Terminal command input"
              autoComplete="off"
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck="false"
              disabled={busy}
            />
            <span className="term__caret" aria-hidden="true" />
          </div>
        </div>
      </div>
    </section>
  );
}

/* ------------------------------------------------------------------ */

function TermLine({ line: l, onRun }) {
  if (l.post) {
    return (
      <div className={`term__line term__line--${l.type || 'out'}`}>
        <a className="term__post" href={l.post.url}>
          <span className="term__post-title">{l.post.title}</span>
          <span className="term__post-meta">
            {l.post.date}
            {l.post.categories?.length ? ` · ${l.post.categories.join(', ')}` : ''}
            {l.post.tags?.length ? ` · ${l.post.tags.slice(0, 4).join(' · ')}` : ''}
          </span>
        </a>
      </div>
    );
  }

  if (l.prompt) {
    return (
      <div className="term__line term__prompt-line">
        <span className="term__ps1">{PS1}</span>
        <span className="term__ps2">~/{HOST} $</span>
        <span className="term__cmd">{l.text}</span>
      </div>
    );
  }

  if (l.extra?.href) {
    const external = l.extra.external;
    return (
      <div className={`term__line term__line--${l.type || 'out'}`}>
        <a
          className="term__link"
          href={l.extra.href}
          {...(external ? { target: '_blank', rel: 'noreferrer' } : {})}
        >
          {l.text}
        </a>
      </div>
    );
  }

  if (!l.text) return <div className="term__line term__line--out">&nbsp;</div>;

  if (l.type === 'ascii') {
    return <pre className="term__ascii">{l.text}</pre>;
  }

  return <div className={`term__line term__line--${l.type || 'out'}`}>{l.text}</div>;
}
