import './Services.css';

const SERVICES = [
  {
    tag: 'SA',
    title: 'Solution architecture & demos',
    body: 'Mapping SAST, DAST, IAST, SCA, and fuzzing capability onto your existing SDLC, then showing it running against something closer to your real codebase than a sample repo.',
  },
  {
    tag: 'POC',
    title: 'Proof of concept engineering',
    body: 'Scoped, time-boxed PoCs so your evaluation reflects your environment — your languages, your build system, your findings — rather than a curated best-case scenario.',
  },
  {
    tag: 'IMPL',
    title: 'Implementation & DevSecOps integration',
    body: 'Beyond the demo: hands-on installation and configuration of the AppSec products themselves — SAST, DAST, IAST, SCA — and wiring them into CI/CD so scanning becomes a normal part of the build, not a gate developers route around.',
  },
  {
    tag: 'RFP',
    title: 'RFP, RFI & technical advisory',
    body: 'Accurate, specific technical responses during procurement, and straight answers in evaluation meetings — including where a tool is genuinely not the right fit.',
  },
];

export default function Services() {
  return (
    <section id="services" className="services">
      <div className="wrap">
        <div className="section-tag"><span className="dash" />Services</div>
        <h2 className="services__heading">What I bring to your evaluation</h2>
        <p className="services__sub">
          Work that's judged on whether your team can make a confident decision
          and get the product running in production afterward — not on how
          polished the deck looked.
        </p>

        <div className="services__grid">
          {SERVICES.map((s) => (
            <article className="service-card" key={s.tag}>
              <span className="service-card__tag mono">{s.tag}</span>
              <h3>{s.title}</h3>
              <p>{s.body}</p>
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}
