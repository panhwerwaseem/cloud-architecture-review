# Changelog

All notable changes to this skill are recorded here. Versions follow [Semantic Versioning](https://semver.org).

## 0.1.0 - 2026-11-06

### Added

- `SKILL.md` with the review protocol: seven hard rules and an eight-step workflow.
- `scripts/iac_inventory.py`: inventory of Terraform, CloudFormation JSON, Kubernetes and Compose files by cloud and category, with findings, "not evaluated" items, and categories not found in the code.
- `scripts/iac_checks.py`: fifteen checks for AWS, Azure and Google Cloud resource types, and a listing of every check and the types it reads.
- `scripts/tf_reader.py`: a brace-matching reader for Terraform files that evaluates literal values only.
- References for the pillar checklists, the questions the code cannot answer, and the exact list of known resource types and checks.
- Four fixtures with planted weaknesses (AWS, Azure, Google Cloud with Kubernetes, CloudFormation with Compose), one clean fixture, five eval cases, and trigger queries.
- Unit tests, a format validator, and a CI workflow.
