import './About.css';

const POINTS = [
  {
    label: 'A technical advisor, not a demo script',
    body: "I've worked application security, offensive security, and DevSecOps enough to answer the follow-up questions honestly — including the ones that don't have a flattering answer.",
  },
  {
    label: 'Solutions grounded in your environment',
    body: 'Demos, PoCs, and the implementation that follows are built around your SDLC, your pipelines, and your risk priorities — not a generic dataset that looks good on a slide.',
  },
  {
    label: 'Always widening the aperture',
    body: "I'm currently deepening my offensive and application security expertise while exploring blockchain and smart contract security, so the advice I give accounts for where risk is heading, not just where it's been.",
  },
];

export default function About() {
  return (
    <section id="about" className="about">
      <div className="wrap about__grid">
        <div className="section-tag"><span className="dash" />About</div>

        <div className="about__body">
          <h2 className="about__heading">
            Presales that respects both sides of the table
          </h2>
          <p className="about__intro">
            I'm a cybersecurity professional working as a Presales Specialist,
            helping organizations strengthen their security posture and adopt
            modern application security practices. That covers technical
            consultations, solution design, product demos and PoCs, and — once
            a customer decides to move forward — the hands-on implementation
            that gets AppSec tooling actually running in their environment.
            Earlier time spent on the offensive side — penetration testing,
            vulnerability analysis, and SOC exposure — is what grounds these
            conversations in how systems actually get compromised, not just
            how a datasheet reads.
          </p>

          <ul className="about__points">
            {POINTS.map((p) => (
              <li key={p.label}>
                <h3>{p.label}</h3>
                <p>{p.body}</p>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </section>
  );
}
