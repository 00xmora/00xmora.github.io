import './Footer.css';

export default function Footer() {
  return (
    <footer className="footer">
      <div className="wrap footer__inner">
        <span className="mono">Omar Samy — Cybersecurity Presales Specialist</span>
        <span className="mono">© {new Date().getFullYear()}</span>
      </div>
    </footer>
  );
}
