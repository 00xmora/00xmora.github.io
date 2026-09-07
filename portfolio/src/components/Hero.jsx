import { Link } from 'react-router-dom';
import photo from '../assets/omar.jpg';
import './Hero.css';

export default function Hero() {
  return (
    <section id="top" className="hero">
      <div className="wrap hero__grid">
        <div className="hero__text">
          <div className="hero__status mono">
            <span className="hero__dot" />
            Available for new engagements
          </div>

          <h1 className="hero__name">Omar Samy</h1>
          <p className="hero__role mono">Cybersecurity Presales Specialist</p>

          <p className="hero__lede">
            I sit on your side of the evaluation table. From requirements gathering
            through demos, proofs of concept, and solution architecture, my job is
            to show — not just tell — how application security tooling fits the way
            your teams actually ship code.
          </p>

          <div className="hero__actions">
            <a className="btn btn--primary" href="mailto:omarsselim00@gmail.com">Start a conversation</a>
            <Link className="btn btn--ghost" to="/services">See how I can help</Link>
          </div>

          <div className="hero__meta mono">6th of October, Giza, Egypt · Remote-friendly</div>
        </div>

        <div className="hero__photo-col">
          <div className="hero__frame">
            <span className="hero__corner hero__corner--tl" />
            <span className="hero__corner hero__corner--tr" />
            <span className="hero__corner hero__corner--bl" />
            <span className="hero__corner hero__corner--br" />
            <img src={photo} alt="Portrait of Omar Samy" />
          </div>
          <div className="hero__caption mono">SUBJECT: omar.samy — ROLE: presales / appsec</div>
        </div>
      </div>
    </section>
  );
}
