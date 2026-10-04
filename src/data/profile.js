/**
 * Single source of truth for everything about me.
 * Both the page components and the terminal read from here, so the
 * terminal can never drift out of sync with the rest of the site.
 */

export const profile = {
  name: 'Omar Samy',
  handle: '00xmora',
  role: 'Cybersecurity Presales Engineer',
  tagline: 'Breaking apps, not hearts',
  location: '6th of October, Giza, Egypt',
  availability: 'Available for new engagements',
  remote: 'Remote-friendly',
  email: 'omarsselim00@gmail.com',
  twitter: 'https://twitter.com/00xmora',
  github: 'https://github.com/00xmora',
  linkedin: 'https://linkedin.com/in/00xmora',
  facebook: 'https://www.facebook.com/00xmora',
  calendly: 'https://calendly.com/00xmora',
  education: 'B.Sc. Computer Science, Minor in IT — Cairo University',
  bio: "I sit on your side of the evaluation table. From requirements gathering through demos, proofs of concept, and solution architecture, my job is to show — not just tell — how application security tooling fits the way your teams actually ship code.",
};

export const links = [
  { label: 'Email', value: 'omarsselim00@gmail.com', href: 'mailto:omarsselim00@gmail.com' },
  { label: 'Book a call', value: 'calendly.com/00xmora', href: 'https://calendly.com/00xmora' },
  { label: 'LinkedIn', value: 'in/00xmora', href: 'https://linkedin.com/in/00xmora' },
  { label: 'GitHub', value: 'github.com/00xmora', href: 'https://github.com/00xmora' },
  { label: 'X / Twitter', value: '@00xmora', href: 'https://twitter.com/00xmora' },
  { label: 'Blog', value: '00xmora.github.io/posts/', href: '/posts/' },
];

export const services = [
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

export const experience = [
  {
    period: 'Sep 2025 — Present',
    title: 'Cybersecurity Engineer | Presales Engineer',
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

export const skillGroups = [
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

export const certifications = [
  {
    name: 'Certified AppSec Practitioner (CAP)',
    body: 'Secure coding, threat modeling, application risk assessment.',
  },
  {
    name: 'Certified Network Security Practitioner (CNSP)',
    body: 'Network security, risk assessment, infrastructure protection.',
  },
  {
    name: 'eJPTv1 — eLearnSecurity',
    body: 'Foundational penetration testing and security principles.',
  },
  {
    name: 'AWS Academy Cloud Foundations',
    body: 'AWS core services, cloud security, architecture, and compliance.',
  },
];

export const aboutPoints = [
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
