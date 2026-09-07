import { Link } from 'react-router-dom';
import Hero from '../components/Hero';
import './Home.css';

const LINKS = [
  { to: '/about', tag: '01', title: 'About', body: 'Background, and how I approach the presales side of security.' },
  { to: '/services', tag: '02', title: 'Services', body: 'What I actually do for you — from architecture to implementation.' },
  { to: '/experience', tag: '03', title: 'Experience', body: 'Where this comes from — Prosoft, and offensive security before that.' },
  { to: '/skills', tag: '04', title: 'Skills', body: 'Toolkit and certifications across AppSec, offensive security, and cloud.' },
  { to: '/blog/', tag: '05', title: 'Blog', body: 'Writeups, CTFs, and research notes from my technical blog.', external: true },
  { to: '/contact', tag: '06', title: 'Contact', body: "Ways to reach me, and what to send if you're evaluating tooling." },
];

export default function Home() {
  return (
    <>
      <Hero />
      <section className="quicklinks">
        <div className="wrap quicklinks__grid">
          {LINKS.map((l) => {
            const Tag = l.external ? 'a' : Link;
            const linkProp = l.external ? { href: l.to } : { to: l.to };
            return (
              <Tag className="quicklink" key={l.to} {...linkProp}>
                <span className="quicklink__tag mono">{l.tag}</span>
                <h3>{l.title}</h3>
                <p>{l.body}</p>
                <span className="quicklink__arrow" aria-hidden="true">&rarr;</span>
              </Tag>
            );
          })}
        </div>
      </section>
    </>
  );
}
