# Moamen Abdelfattah - AI-Native Engineering Portfolio

I build and evaluate AI-assisted software workflows with an emphasis on rapid iteration, reproducible testing, explicit authority boundaries, and evidence-backed review.

This portfolio is intentionally concise. It links to public code where possible and uses sanitized case studies where the underlying repository or product is private.

## Selected work

### 1. tauGuardian - LLM Coding Safety Harness

**Public code:** this repository.

A model-agnostic Python harness for comparing baseline LLM-generated code against a wrapped workflow that adds behavioral tests, linting, security checks, bounded repair, and optional Docker isolation.

What it demonstrates:

- Python implementation and experiment tooling.
- pytest-based behavioral validation.
- AST/static security checks for common coding hazards.
- A bounded repair loop instead of unlimited autonomous retries.
- Explicit OK / ABSTAIN / VETO decision semantics.
- Reproducible experiment outputs and analysis utilities.

Start with the main [README](README.md).

### 2. Governed Multiplayer AI - Private R&D

**Sanitized case study:** [case-studies/governed-multiplayer-ai.md](case-studies/governed-multiplayer-ai.md)

A governed AI-assisted software-engineering workflow that separates human ownership, control-tower coordination, implementation, and independent verification so the coding agent cannot approve its own work.

What it demonstrates:

- Claude Code and Codex used in distinct implementation/review roles.
- Exact Git candidate identity and stale-state handling.
- Criteria locks, evidence-backed handoffs, negative tests, and bounded remediation.
- Python governance/publisher components and security-focused mutation testing.
- Explicit limits: private R&D, not presented as a production-deployed platform.

### 3. Controlled Web-Product Delivery - Private Product Work

**Sanitized case study:** [case-studies/controlled-product-delivery.md](case-studies/controlled-product-delivery.md)

A summary of how I translate ambiguous business or human workflows into structured bilingual web-product journeys, schemas, permissions, QA criteria, release gates, and controlled rollout plans while coordinating AI-assisted implementation.

## Evidence index

For a recruiter or technical reviewer who wants a fast proof map, see [evidence/selected-evidence-index.md](evidence/selected-evidence-index.md).

## Short demo

A 90-second walkthrough script showing my AI-native development workflow is available at [demo/90-second-agent-workflow-demo.md](demo/90-second-agent-workflow-demo.md).

## Technical focus

Python | Git/GitHub | pytest | JSON | SQL-backed systems | Claude Code | Codex | ChatGPT | AI-agent tasking | negative and mutation testing | static/AST security checks | reproducible evidence | human-in-the-loop controls | product workflow design

## Working principle

AI is a force multiplier, not an authority substitute. I use coding agents aggressively for exploration and implementation, while keeping acceptance criteria, test evidence, independent review, and consequential release decisions explicit.

## Contact

Moamen Abdelfattah - Cairo, Egypt  
LinkedIn: https://www.linkedin.com/in/moamen-magdy-2984b179  
Email: moamen.magdi.pro@gmail.com
