# cloud-architecture-review

**An agent skill that reviews a system against reliability, security and cost pillars from its infrastructure code, starting from a scripted inventory that says what it could not evaluate instead of guessing.**

Left alone, a coding agent asked for an architecture review tends to skim a few Terraform files and produce a confident list: findings with no file behind them, "there is no monitoring" because none was in the repository, a variable's default reported as the deployed value, a verdict on instance sizes with no traffic numbers, and a monthly cost estimate from memory. This skill replaces that with a protocol and three scripts: inventory first, every finding tied to a file and a resource, "not evaluated" kept separate from both findings and passes, questions about recovery targets and traffic before any sizing judgement, and no cost figures without the user's pricing data.

It reads Terraform, CloudFormation, Kubernetes and Compose files for AWS, Azure and Google Cloud. It reads code only: it never calls a cloud API.

Works with Claude Code, and with any agent that reads the open [Agent Skills](https://agentskills.io) format (Codex, Cursor, GitHub Copilot, Gemini CLI and others).

## What it looks like

Scanning one file of a fixture. Port 443 open to the internet is not a finding; ports 22 and 5432 are; the security group built from a `dynamic` block is reported as not evaluated:

```console
$ python3 scripts/iac_inventory.py evals/files/shop-aws/network.tf
Scanned evals/files/shop-aws/network.tf: 1 terraform file(s)

INVENTORY (4 resources)
  aws        network       aws_security_group x3, aws_security_group_rule x1

FINDINGS (2 high, 1 medium, 0 low)
  [high] open-ingress  aws_security_group.web  (network.tf:13)
      Inbound traffic from 0.0.0.0/0 is allowed on port 22 (SSH).
  [high] open-ingress  aws_security_group.db  (network.tf:33)
      Inbound traffic from 0.0.0.0/0 is allowed on port 5432 (PostgreSQL).
  [medium] open-ingress  aws_security_group_rule.metrics  (network.tf:57)
      Inbound traffic from 0.0.0.0/0 is allowed on port 9100.

NOT EVALUATED (1). The script did not guess these. Read the code or ask; they are neither findings nor passes.
  aws_security_group.internal  (network.tf:42)
      ingress is inside a dynamic "ingress" block (line 46)

NOT FOUND IN THE SCANNED CODE. This is not proof of absence in the cloud account; ask.
  aws: no compute, data, identity, observability resources

RESULT: 2 finding(s) at or above 'high'. Still open: 1 item(s) not evaluated.
```

The exit code is 1 because of the high findings.

Seeing exactly what the Terraform reader saw in a file. String values are hidden unless you pass `--values`, so a password in a variable file is not copied into your terminal log:

```console
$ python3 scripts/tf_reader.py evals/files/shop-aws/prod.tfvars
evals/files/shop-aws/prod.tfvars
  ami = "<string, 21 chars>"
  backup_days = 7
  internal_cidrs = ["<string, 12 chars>"]
  reporting_multi_az = true
  reporting_password = "<string, 31 chars>"
```

## Install

Pick one route. Installing through more than one gives you the skill twice.

**Claude Code (plugin)**

```
/plugin install cloud-architecture-review --marketplace panhwerwaseem/cloud-architecture-review
```

On Claude Code versions before 2.1.275, use two steps:

```
/plugin marketplace add panhwerwaseem/cloud-architecture-review
/plugin install cloud-architecture-review@panhwerwaseem-cloud-architecture-review
```

**Any agent (skills CLI)**

```bash
npx skills add panhwerwaseem/cloud-architecture-review
```

**Manual**

Copy the `skills/cloud-architecture-review` folder into `.claude/skills/` (Claude Code) or `.agents/skills/` (cross-agent) in your project, or into the same folder under your home directory.

To pin a release, add the tag: `/plugin marketplace add panhwerwaseem/cloud-architecture-review#v0.1.0` or `npx skills add panhwerwaseem/cloud-architecture-review@v0.1.0`. Third-party plugins do not update automatically; run `claude plugin update cloud-architecture-review@panhwerwaseem-cloud-architecture-review` to update.

## Use

Describe the problem and the skill loads on its own:

> We launch next week. The Terraform is in ./infra. Can you review the architecture and tell me what would bite us in production?

In Claude Code you can also call it directly with `/cloud-architecture-review`.

## What is in the skill

| File | Purpose |
|---|---|
| `SKILL.md` | The protocol: seven hard rules and an eight-step workflow from inventory to report |
| `scripts/iac_inventory.py` | Walks a directory for Terraform, CloudFormation JSON, Kubernetes and Compose files. Prints the resources by cloud and category (compute, data, network, identity, observability), the findings, the items not evaluated, the categories not found in the code, and the files it could not read |
| `scripts/iac_checks.py` | The fifteen checks: databases without a standby or backups, storage without encryption, public databases and buckets, firewall rules open to the internet, missing deletion protection, single instances, secrets written as literals, unbounded log retention. Run it to list every check and the resource types it reads |
| `scripts/tf_reader.py` | A brace-matching reader for `.tf` and `.tfvars` files. It evaluates literal values only and marks everything else as not evaluated. Run it on a file to see what it saw |
| `references/pillar-checklists.md` | What to review by reading under each pillar, beyond what the script checks |
| `references/questions-to-ask.md` | The questions code cannot answer (recovery objectives, traffic, data classification, controls set outside the code) and what each answer changes |
| `references/known-types-and-checks.md` | Exactly which resource types the script knows, which attribute each check reads, and which provider default it relies on |
| `evals/` | Four fixtures with planted weaknesses (AWS, Azure, Google Cloud with Kubernetes, CloudFormation with Compose), one clean fixture, five eval cases, and trigger queries |

### What "not evaluated" means

The Terraform reader is not a full HCL parser and does not run Terraform. It evaluates literals: `true`, `0`, `"ZONAL"`, and lists and maps of those. A value that comes from a variable, a local, a function call, a conditional, a module or a `dynamic` block is reported as not evaluated, with the expression as written. Variable defaults and `.tfvars` values are never substituted, because the script cannot know which environment is deployed. CloudFormation intrinsic functions such as `Ref` are treated the same way.

A check reports a finding for an unset attribute only where the documented provider default is the weak setting, and the finding says so. Where the script is not prepared to state a default, it reports not evaluated.

### What it does not do

- It does not read cloud accounts, Terraform state or plan files. A resource missing from the code may exist elsewhere.
- It does not check IAM policies. The checklist tells the agent to read them.
- It does not read modules' inputs, Terraform JSON syntax, Helm charts, Kustomize overlays, CDK or Pulumi source, Bicep or ARM templates.
- It does not estimate cost.
- Its secret check matches attribute names. It is not a secret scanner.

### YAML

The Python standard library has no YAML parser, and the script does not include one. JSON is read natively. YAML files are read when PyYAML is installed. Without it, the script stops with exit code 2 and lists the options: install PyYAML, convert the files to JSON, or pass `--skip-yaml` to scan everything else and list the YAML files as not read. CloudFormation YAML that uses short tags such as `!Ref` has to be converted to JSON first.

## Requirements

- Python 3.9 or later
- No packages to install and no network access
- Optional: PyYAML, only to read YAML files

## What it reads, writes and contacts

- **Reads:** `.tf`, `.tfvars`, `.json`, `.yaml` and `.yml` files under the path you pass. Directories and files whose names start with a dot, and `node_modules`, are skipped.
- **Writes:** nothing. Output goes to the terminal.
- **Runs:** nothing. No `terraform`, no cloud CLI, no `kubectl`.
- **Contacts:** nothing. The scripts contain no network code; CI enforces this.
- **Secrets:** the inventory reports where a secret-looking value is written and never prints the value.
- **Permissions:** the skill pre-approves no tools. Your agent asks before running commands, as usual.

See [SECURITY.md](SECURITY.md).

## Testing status

- The scripts have unit tests that run in CI on Python 3.9 and 3.12, together with a validator for the skill format and plugin manifests. The tests assert that each fixture reports exactly its planted weaknesses and that the clean fixture reports none.
- The attribute names and defaults the checks rely on were written from provider documentation. They have not been verified by applying the fixtures to real cloud accounts. `references/known-types-and-checks.md` lists every one so you can check them against the provider version you use.
- The eval cases in `skills/cloud-architecture-review/evals/` are in the [skill-creator](https://github.com/anthropics/skills/tree/main/skills/skill-creator) format. A with-skill versus without-skill score has not been published yet; results are welcome as an issue or pull request.

## Development

```bash
python3 tools/validate.py              # skill format, manifests, no-network check
python3 -m unittest discover -s tests  # script unit tests
```

## License

[MIT](LICENSE)
