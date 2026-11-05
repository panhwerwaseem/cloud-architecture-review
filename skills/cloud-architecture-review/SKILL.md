---
name: cloud-architecture-review
description: Reviews a system's cloud architecture against reliability, security and cost pillars from the repository's infrastructure code (Terraform, CloudFormation, Kubernetes and Compose files) on AWS, Azure and Google Cloud, starting from a scripted inventory and weakness scan. Use when the user asks for an architecture review, a well-architected review, a production readiness or pre-launch infrastructure check, a security or reliability review of Terraform or CloudFormation, or asks about single points of failure, public exposure, missing backups, unencrypted storage or hard-coded secrets in infrastructure code, or says is our infra production ready or review my infrastructure.
license: MIT
compatibility: Requires Python 3.9 or later to run the bundled scripts. No network access and no extra packages needed. YAML files are read only when PyYAML is installed; Terraform and JSON files need nothing extra.
metadata:
  author: panhwerwaseem
  version: "0.1.0"
---

# Cloud architecture review

A review is done when the user has four things: an inventory of what the code
declares; findings that each cite a file and a resource and were checked
against the cited code; a list of what could not be evaluated and what the
code cannot show; and judgements on redundancy, sizing and cost that rest on
targets the user stated, not on targets you assumed.

Paths in this file are relative to this skill's directory.

## Hard rules

1. **Inventory first.** Run `scripts/iac_inventory.py` before describing or
   judging the architecture. Do not review from file names, a README, or what
   such systems usually look like.
2. **Every finding cites a file and a resource.** Give the line for Terraform
   or the JSON path for templates and manifests, and read the cited code
   before reporting it. If you cannot point at code, it is a question for the
   user, not a finding.
3. **Absent from the code is not absent from the account.** Never write
   "there is no monitoring", "no backups exist" or "no WAF". Write "not found
   in the scanned code" and ask where it is managed. Other repositories, the
   console, and organisation-level policy are all invisible here.
4. **Not evaluated is neither a pass nor a finding.** For each item the
   script lists as not evaluated, read the variable, the `.tfvars` file for
   the environment in question, or the module source, or ask. Say which
   environment a resolved value applies to. Never present a variable default
   as the deployed value.
5. **Ask for targets before judging sizing or redundancy.** Recovery time and
   recovery point objectives, traffic, and data classification decide whether
   a single zone, an instance size or a retention period is acceptable. Until
   you have them, report the fact and what it implies, not a verdict. If the
   user cannot answer, state your assumption and label it as one.
6. **No cost figures without the user's pricing data.** No currency amounts,
   monthly estimates or percentage savings from memory. Without a bill, a
   pricing export or a calculator result from the user, cost observations are
   structural only: what runs all the time, what grows without bound, what
   cannot scale down.
7. **Read-only, and never repeat a secret.** Do not run `terraform`, cloud
   CLIs or `kubectl` against live systems, and do not edit infrastructure code
   during the review. When a secret is written in a file, cite its location;
   do not copy its value into the report or the conversation.

## Workflow

### 1. Fix the scope

Establish which directory holds the system under review and which
environment the user cares about. A repository often holds several systems
and several environments; review one at a time.

### 2. Take the inventory

```bash
python3 scripts/iac_inventory.py <path>
python3 scripts/iac_inventory.py <path> --json    # full detail, every resource
```

The script reads Terraform, CloudFormation JSON, and Kubernetes and Compose
files. It prints the resources by cloud and category, the findings, the items
it did not evaluate, the categories it did not find, and the files it could
not read. Exit code 0 means no finding at or above `--fail-on` (default
`high`), 1 means at least one, 2 means it could not run: read the message.

If it stops because YAML files are present and PyYAML is not installed,
follow one of the options it prints. Use `--skip-yaml` only when the YAML
files are not part of the system under review, and say so in the report.

### 3. Confirm the inventory with the user

Summarise it in a few lines and ask what is missing: resources in other
repositories, resources created by hand, shared networking, organisation
policy. Treat "files not read" and "uncategorised" types as gaps in the
review and name them.

### 4. Ask what the code cannot answer

`references/questions-to-ask.md` lists the questions and what each one
changes. Ask at least for recovery objectives, traffic, and data
classification, in one message. Continue with the parts of the review that do
not depend on the answers.

### 5. Resolve the items that were not evaluated

For a variable, read its declaration and the `.tfvars` file for the
environment. For a module, read its source if it is in the repository. To see
exactly what the reader saw in one file:

```bash
python3 scripts/tf_reader.py <file.tf>
```

What you cannot resolve stays in the report as an open item.

### 6. Verify the findings and review each pillar

Read the cited lines for every finding. `references/known-types-and-checks.md`
states exactly which attributes each check reads and which provider default
it relies on; for a finding that says "is not set (documented default: ...)",
confirm the default against the provider version the repository pins.

Then work through `references/pillar-checklists.md` for what the script does
not check, IAM policies above all. Anything you add must meet rule 2.

### 7. Rank against the stated targets

Order the findings by the harm they can do to this system given the user's
answers, not by the script's severity alone. An unencrypted volume holding
public data and a public database holding payment data are not the same
finding. Where targets are missing, say which ranking depends on them.

### 8. Report

```
Scope:           <path, environment, what was and was not scanned>
Inventory:       <resources by cloud and category, in a few lines>
Targets:         <RTO, RPO, traffic, data classification: stated by the user, or assumed and labelled>

Findings
  <severity>  <pillar>  <resource>  <file:line or file: JSON path>
      <what the code says, what it implies, the fix>

Not evaluated:   <each item, and how it was resolved or that it is still open>
Not found in the scanned code: <categories, with the question asked about each>
Not reviewed:    <files not read, uncategorised types, modules, anything outside the code>
Cost:            <structural observations only, or figures with the user's pricing source named>
Questions:       <unanswered questions that would change the findings above>
```

## Edge cases

- **No infrastructure code found (exit code 2).** Say so. A review based on
  the user's description alone is a discussion, not a review of evidence;
  label every statement in it as unverified.
- **Several environments from one codebase.** The script reports the code,
  not an environment. Resolve variables separately for each `.tfvars` file
  and say which findings apply to which environment.
- **Modules.** Module files inside the scanned path are read as ordinary
  files, with their inputs unresolved. Remote and registry modules are not
  read at all. Either way the module call is listed as not evaluated.
- **Helm, Kustomize, CDK, Pulumi, Bicep, ARM, Terraform JSON.** Not read.
  Ask the user for rendered output (`helm template`, `cdk synth`) and scan
  that, or mark the area as not reviewed.
- **A finding that rests on a default.** Providers change defaults between
  major versions. Check before reporting.
- **The user asks for one pillar only.** Still take the inventory; report the
  one pillar.
- **The user asks for fixes.** Finish the report first. Then change code only
  for the findings the user picks, and do not apply it.
