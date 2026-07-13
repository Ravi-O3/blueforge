# 07. Documentation Generation

Good documentation is half the portfolio value: it is the part a hiring manager actually reads.
BlueForge treats docs as first-class. This section is the index of every document type and the
reusable templates that keep them consistent.

## Document types and where they live

| Document | Location | Purpose |
|----------|----------|---------|
| README | `README.md` | Front door: what/why/quickstart/architecture |
| Master blueprint | `docs/00-master-blueprint.md` | The whole design in one file |
| Architecture | `docs/03-architecture.md` | Components, data flow, trade-offs |
| Installation guide | `docs/installation.md` | Zero-to-running setup |
| Threat model | `docs/threat-model.md` | What we defend, assets, assumptions |
| Detection guide | `docs/detection-guide.md` | How to author, test, and tune a detection |
| Investigation playbooks | `docs/playbooks/` (from template) | Step-by-step triage per alert type |
| Lab docs | `labs/*/README.md` (from template) | Reproducible attack/detection exercises |
| Lessons learned | `docs/lessons/` (from template) | Reflection log; strong interview fuel |

## Templates (in `docs/templates/`)

- `detection-template.md` - every new rule starts here.
- `investigation-playbook-template.md` - every alert type gets a playbook.
- `lab-template.md` - every attack simulation is documented reproducibly.
- `lessons-learned-template.md` - short reflection after each meaningful session.

## README template (skeleton)

A strong security-project README has, in order: one-line description, badges, a "why this exists"
paragraph, an architecture diagram, a quickstart that works from a clean clone, the repo layout,
a detection-coverage note, the roadmap, and links into `docs/`. BlueForge's own README is the
worked example; copy its structure for any future project.

## Writing standards

Lead with the answer. Prefer prose over bullet soup. For any security concept, cover four things:
why it exists, how it works, how an attacker abuses it, and how a defender detects it. Keep diagrams
in Mermaid so they live in git and render on GitHub. Never document a secret; document how to
configure one via `.env`.
