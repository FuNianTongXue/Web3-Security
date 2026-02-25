# Web3-Security

A repository for Web3 security engineering assets, including:
- SCaudit refactored platform codebase
- Website demo project
- Security review materials (audit, threat modeling, compliance)
- SDLC / DevSecOps planning documents

## Repository Structure

- `scaudit-refactored/`: Main security platform (Go backend + web modules)
- `official-website-demo/`: Website demo (frontend + backend + docker-compose)
- `code-audit-materials/`: Code-audit reference spreadsheets
- `threat-modeling-materials/`: Threat-modeling templates and scoring sheets
- `compliance-materials/`: Compliance and log-ingestion documents
- `SDLC_DevSecOps_Optimization_Plan.md`: SDLC/DevSecOps optimization plan

## Quick Start

### 1) Run SCaudit platform

```bash
cd scaudit-refactored
make run
```

### 2) Run website demo

```bash
cd official-website-demo
docker compose up -d --build
```

## Development Notes

- Use feature branches for changes.
- Keep generated artifacts, caches, and local runtime files out of git.
- Prefer English names for top-level directories and key docs.

## License

This repository is licensed under the MIT License. See [LICENSE](./LICENSE).
