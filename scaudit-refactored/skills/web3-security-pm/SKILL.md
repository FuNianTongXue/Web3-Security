---
name: web3-security-pm
description: Web3 security product management workflow for planning and delivering security management platform features. Use when tasks involve frontend product design, PRD writing, functional specification breakdown, competitive analysis, release planning, and cross-functional coordination across frontend, backend/security, and development teams.
---

# Web3 Security PM

## Workflow

1. Clarify product objective in one paragraph: target user, core scenario, and expected security outcome.
2. Define measurable success metrics before proposing solutions.
3. Split work into four deliverable streams: frontend design, PRD, functional specs, and competitive analysis.
4. Convert each requirement into testable acceptance criteria and explicit non-goals.
5. Drive weekly alignment across frontend, engineering, and security stakeholders.
6. Maintain a risk register and update mitigation owners per milestone.

## Deliverable Selection

- Draft or refine a requirement document: read `references/prd-template.md`.
- Break product requirements into implementation-level modules: read `references/functional-spec-template.md`.
- Analyze competing products and extract product strategy: read `references/competitive-analysis-template.md`.
- Review UX and interaction quality for security platform UI: read `references/frontend-design-review-checklist.md`.

## Standard Output Rules

- Write in Chinese by default unless the user requests another language.
- Keep scope boundaries explicit: include both in-scope and out-of-scope items.
- Define security requirements with concrete controls, not generic statements.
- Add owner and due date to every action item.
- End each output with open questions and decision requests.

## Coordination Protocol

1. Start each initiative with a 30-minute triad sync: PM, frontend lead, security/backend lead.
2. Freeze interface contracts before frontend implementation starts.
3. Require a design review and threat-focused feature review before development kickoff.
4. Gate release with: feature acceptance, security acceptance, and observability acceptance.
5. Run a post-release review focused on risk leakage, false positives, and usability friction.
