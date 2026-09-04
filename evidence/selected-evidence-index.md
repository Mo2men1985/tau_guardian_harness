# Selected Engineering Evidence Index

This index is designed for a fast technical review. It separates directly inspectable public evidence from private/sanitized evidence.

## Public code - tauGuardian

Repository root: https://github.com/Mo2men1985/tau_guardian_harness

Useful entry points:

- `README.md` - system purpose, decision model, sandboxing, benchmark structure, and usage.
- `harness.py` - baseline versus wrapped LLM code-generation workflow.
- `ast_security.py` - AST-based security checks.
- `docker_sandbox.py` - optional isolated execution surface.
- `analyze_results.py` and related analysis utilities - experiment/result processing.
- `tests/` - pytest validation for the coding tasks and controls.
- `tasks/` / `tg_code/` - task specifications and code-under-test surfaces.

What this evidence supports:

- Hands-on Python development.
- AI coding workflow experimentation.
- Automated testing and security checks.
- Bounded repair / fail-closed decision logic.
- Reproducible evaluation thinking rather than prompt-only prototyping.

## Sanitized case study - Governed Multiplayer AI

Case study: `case-studies/governed-multiplayer-ai.md`

What it supports:

- Claude Code used as an implementation agent.
- Codex used in an independent verification role.
- Exact Git-candidate review boundaries.
- Acceptance criteria, evidence requirements, and negative/mutation testing.
- Human authority and separation-of-duties design for agentic software engineering.

Private evidence available for controlled review can include selected repository structure, test output, sanitized audit reports, and exact-candidate review examples. It does not include secrets, customer data, or unrestricted access to private intellectual property.

## Sanitized case study - Controlled Product Delivery

Case study: `case-studies/controlled-product-delivery.md`

What it supports:

- Translating ambiguous requirements into product journeys, schemas, permissions, QA criteria, and release gates.
- Supabase/Vercel-backed web-product delivery in selected private projects.
- Cross-functional coordination between domain owners, AI-assisted implementation, testing, and review.

## Evidence discipline

A claim is presented as public proof only when a reviewer can inspect it directly. Private-project claims are labeled as sanitized case studies and can be supported through controlled review when needed. Experimental work is not represented as production deployment unless production evidence exists.
