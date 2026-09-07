import './Experience.css';

const ROLES = [
  {
    period: 'Sep 2025 — Present',
    title: 'Cybersecurity Engineer | Presales Specialist',
    org: 'Prosoft · Full-time — Egypt, On-site',
    points: [
      'Lead the full technical business cycle — discovery sessions, requirements analysis, and technical solution architecture — for enterprise clients.',
      'Deliver technical demos, PoCs, and security solution design to help customers secure their SDLC and software supply chain and adopt DevSecOps practices.',
      'Implement and support Black Duck (formerly Synopsys) AppSec solutions including SAST, DAST, IAST, SCA, fuzzing, IDE plugins, and Polaris Cloud in client environments.',
      'Act as technical advisor through evaluation and selection, and support sales teams on RFPs, RFIs, and technical clarifications.',
    ],
  },
  {
    period: 'Jul 2023',
    title: 'Offensive Security Engineer (Intern)',
    org: 'Security Meter, Giza, Egypt',
    points: [
      'Performed web and network penetration testing using Nmap and Burp Suite.',
      'Gained direct exposure to SOC operations, incident response workflows, and GRC practices.',
      'Contributed to vulnerability analysis, secure configuration reviews, and executive-ready reporting.',
    ],
  },
];

export default function Experience() {
  return (
    <section id="experience" className="experience">
      <div className="wrap">
        <div className="section-tag"><span className="dash" />Experience</div>
        <h2 className="experience__heading">Where this comes from</h2>

        <div className="timeline">
          {ROLES.map((r) => (
            <div className="timeline__item" key={r.title}>
              <div className="timeline__marker" />
              <div className="timeline__period mono">{r.period}</div>
              <div className="timeline__content">
                <h3>{r.title}</h3>
                <p className="timeline__org mono">{r.org}</p>
                <ul>
                  {r.points.map((pt) => (
                    <li key={pt}>{pt}</li>
                  ))}
                </ul>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
