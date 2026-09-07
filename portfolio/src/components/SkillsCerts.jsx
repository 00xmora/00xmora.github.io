import './SkillsCerts.css';

const SKILL_GROUPS = [
  {
    title: 'Presales & solution design',
    items: ['Technical demos', 'PoCs', 'Solution architecture', 'CI/CD integration', 'Customer workshops'],
  },
  {
    title: 'Application security',
    items: ['OWASP Top 10', 'Secure code review', 'Threat modeling', 'SAST', 'DAST', 'SCA', 'IAST', 'Dependency scanning'],
  },
  {
    title: 'Offensive security',
    items: ['Web & network pentesting', 'Burp Suite', 'Nmap', 'Metasploit', 'AD attacks'],
  },
  {
    title: 'Cloud & DevSecOps',
    items: ['CI/CD security', 'Secure SDLC', 'AWS fundamentals'],
  },
];

const CERTS = [
  { name: 'Certified AppSec Practitioner (CAP)', body: 'Secure coding, threat modeling, application risk assessment.' },
  { name: 'Certified Network Security Practitioner (CNSP)', body: 'Network security, risk assessment, infrastructure protection.' },
  { name: 'eJPTv1 — eLearnSecurity', body: 'Foundational penetration testing and security principles.' },
  { name: 'AWS Academy Cloud Foundations', body: 'AWS core services, cloud security, architecture, and compliance.' },
];

export default function SkillsCerts() {
  return (
    <section id="skills" className="skills">
      <div className="wrap skills__grid">
        <div>
          <div className="section-tag"><span className="dash" />Skills</div>
          <h2 className="skills__heading">Toolkit</h2>
          <div className="skills__groups">
            {SKILL_GROUPS.map((g) => (
              <div className="skills__group" key={g.title}>
                <h3>{g.title}</h3>
                <div className="skills__tags">
                  {g.items.map((i) => (
                    <span key={i}>{i}</span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>

        <div>
          <div className="section-tag"><span className="dash" />Certifications</div>
          <h2 className="skills__heading">Credentials</h2>
          <div className="certs">
            {CERTS.map((c) => (
              <div className="certs__item" key={c.name}>
                <h3>{c.name}</h3>
                <p>{c.body}</p>
              </div>
            ))}
          </div>
          <p className="skills__edu mono">
            B.Sc. Computer Science, Minor in IT — Cairo University
          </p>
        </div>
      </div>
    </section>
  );
}
