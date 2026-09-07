import { useEffect, useState } from 'react';
import { NavLink, Link } from 'react-router-dom';
import './Nav.css';

const LINKS = [
  { to: '/about', label: 'About' },
  { to: '/services', label: 'Services' },
  { to: '/experience', label: 'Experience' },
  { to: '/skills', label: 'Skills' },
];

// The blog is a separate, statically-built Jekyll site living at /blog/ —
// a plain link (full page load), not a client-side route.
const BLOG_HREF = '/blog/';

export default function Nav() {
  const [open, setOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 12);
    onScroll();
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  return (
    <header className={`nav ${scrolled ? 'nav--scrolled' : ''}`}>
      <div className="wrap nav__inner">
        <Link to="/" className="nav__logo mono" onClick={() => setOpen(false)}>
          omar<span className="nav__logo-accent">.</span>samy
        </Link>

        <nav className="nav__links">
          {LINKS.map((l) => (
            <NavLink
              key={l.to}
              to={l.to}
              className={({ isActive }) => (isActive ? 'nav__link nav__link--active' : 'nav__link')}
            >
              {l.label}
            </NavLink>
          ))}
          <a href={BLOG_HREF} className="nav__link">Blog</a>
        </nav>

        <Link to="/contact" className="nav__cta mono">Get in touch</Link>

        <button
          className="nav__burger"
          aria-label="Toggle menu"
          aria-expanded={open}
          onClick={() => setOpen((v) => !v)}
        >
          <span />
          <span />
        </button>
      </div>

      {open && (
        <div className="nav__mobile">
          {LINKS.map((l) => (
            <NavLink key={l.to} to={l.to} onClick={() => setOpen(false)}>{l.label}</NavLink>
          ))}
          <a href={BLOG_HREF} onClick={() => setOpen(false)}>Blog</a>
          <Link to="/contact" className="nav__mobile-cta mono" onClick={() => setOpen(false)}>
            Get in touch
          </Link>
        </div>
      )}
    </header>
  );
}
