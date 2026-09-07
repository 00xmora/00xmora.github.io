import './Contact.css';

const LINKS = [
{ label: 'Email', value: '[omarsselim00@gmail.com](mailto:omarsselim00@gmail.com)', href: 'mailto:omarsselim00@gmail.com' },
{ label: 'Book a call', value: 'calendly.com/00xmora', href: 'https://calendly.com/00xmora' },
{ label: 'LinkedIn', value: 'in/00xmora', href: 'https://linkedin.com/in/00xmora' },
{ label: 'GitHub', value: 'github.com/00xmora', href: 'https://github.com/00xmora' },
{ label: 'Blog', value: '00xmora.github.io', href: 'https://00xmora.github.io' },
];


export default function Contact() {
  return (
    <section id="contact" className="contact">
      <div className="wrap">
        <div className="section-tag"><span className="dash" />Contact</div>
        <h2 className="contact__heading">Let's talk about your evaluation</h2>
        <p className="contact__sub">
          Whether you're scoping a PoC, comparing AppSec vendors, or just want a
          second technical opinion — I'm glad to help.
        </p>

        <div className="contact__grid">
          {LINKS.map((l) => (
            <a className="contact__link" href={l.href} key={l.label} target={l.href.startsWith('http') ? '_blank' : undefined} rel="noreferrer">
              <span className="contact__label mono">{l.label}</span>
              <span className="contact__value">{l.value}</span>
            </a>
          ))}
        </div>
      </div>
    </section>
  );
}
