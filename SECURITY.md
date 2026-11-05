# Security

An agent skill is instructions and code that your coding agent will follow and run. Review a skill before installing it, the same way you would review any dependency.

## What this skill does on your machine

| | |
|---|---|
| Reads | `.tf`, `.tfvars`, `.json`, `.yaml` and `.yml` files under the path you give it. Directories and files whose names start with a dot, and `node_modules`, are skipped |
| Writes | Nothing. The scripts print to standard output and standard error only |
| Executes | Nothing. The scripts start no other program: no `terraform`, no cloud CLI, no `kubectl` |
| Network | None. The bundled scripts import no network modules and call no cloud API. `tools/validate.py` checks this in CI |
| Dependencies | Python standard library only. PyYAML is used if it is already installed, to read YAML files; without it the script stops and lists the options |
| Pre-approved tools | None. `SKILL.md` has no `allowed-tools` entry, so your agent's normal permission prompts apply |
| Hooks, MCP servers, background processes | None |

The skill instructs the agent to keep the review read-only: no infrastructure commands and no edits to infrastructure code until you ask for fixes after the report.

## Secrets in the files it reads

Infrastructure repositories sometimes contain secrets, and this skill is often run because of that.

- `iac_inventory.py` reports where a secret-looking value is written (file, resource, line or JSON path, and the attribute name). It never prints the value, in text or JSON output. A test asserts this for every fixture.
- `tf_reader.py` hides literal string values unless you pass `--values`, and never keeps heredoc text.
- Expressions that the scripts could not evaluate are printed as written, for example `multi_az = var.multi_az`. A secret embedded in an interpolated string would appear there.
- The agent still has ordinary file access. `SKILL.md` tells it not to copy secret values into the report or the conversation, but it can read the files.

The secret check matches attribute names. It is not a secret scanner, and a clean result does not mean the repository holds no secrets.

## Limits you should know before trusting a result

- The scripts read code, not cloud accounts. A clean result says nothing about resources created outside the scanned path.
- Values set by variables, modules, dynamic blocks or CloudFormation intrinsic functions are reported as "not evaluated", never guessed.
- Findings that rest on a provider default are written against provider documentation and can go stale when a provider changes a default. The finding text says when it rests on a default.

## Reporting a vulnerability

Please report security problems privately through the repository's **Security** tab ("Report a vulnerability"). If that option is not available, open an issue that says a private channel is needed, without including exploit details.

## Verifying what you install

- Install from a tagged release and read the diff between tags before updating.
- The whole skill is the `skills/cloud-architecture-review/` folder: one Markdown protocol, three Python scripts, three reference files, and eval fixtures.
