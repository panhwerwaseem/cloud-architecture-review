# Questions the code cannot answer

Infrastructure code says what is declared. It does not say what the system is
for, how much load it carries, what its data is worth, or what exists outside
the repository. Ask before judging.

Ask only the questions whose answer would change a finding, and ask them in
one message. If the user does not know, write down the assumption you are
using and label it in the report.

## Always ask

| Question | What the answer changes |
|---|---|
| What is the recovery time objective: how long may the system be down? | Whether single-zone data stores, single instances and manual failover are defects |
| What is the recovery point objective: how much recent data may be lost? | Whether the backup retention, backup frequency and point-in-time recovery settings are enough |
| Which failures must the system survive: one instance, one zone, one region? | How much redundancy to expect, and whether cross-region copies matter |
| What traffic does it carry: typical and peak requests per second, and how fast is it growing? | Whether fixed capacity and the scaling limits fit. Sizing cannot be judged without it |
| What data does it hold: personal, payment, health, credentials, or public? | Severity of every exposure and encryption finding, and whether customer-managed keys or data residency rules apply |

## Scope

| Question | What the answer changes |
|---|---|
| Does this code deploy everything, or do other repositories or teams own parts (network, identity, monitoring)? | Whether a category missing from the inventory is a gap or simply elsewhere |
| Was anything created by hand in the console? | Same |
| Which environment is under review, and which variable file or parameter set deploys it? | How every "not evaluated" variable is resolved |
| Is the code in this branch what is deployed? | Whether findings describe production or a proposal |

## Controls set outside the code

These are commonly set once for an account, subscription, project or
organisation, so their absence from a repository means little. Ask whether
they are in place.

| Cloud | Ask about |
|---|---|
| AWS | Account-level S3 Block Public Access; EBS encryption by default; organisation service control policies; an organisation-wide audit trail |
| Azure | Azure Policy assignments on the subscription or management group; subscription-level diagnostic settings for the activity log |
| Google Cloud | Organisation policy constraints, for example on public access and external IP addresses; audit log configuration |
| Any | Central logging and alerting; who can assume administrative roles; how often keys and credentials are rotated |

## Exposure and access

| Question | What the answer changes |
|---|---|
| Which endpoints are meant to be reachable from the internet? | Whether an open rule is a finding or the design |
| How do operators reach databases and hosts: a VPN, a bastion, a session service? | Whether open administrative ports have any justification, and what to replace them with |
| Is a public bucket or container serving content that is meant to be public? | Severity of public storage findings |

## Operations

| Question | What the answer changes |
|---|---|
| Has a restore from backup been tested, and when? | Whether the backups can be counted on at all |
| Who is alerted when the system fails, and from which signals? | Whether missing alarms in code are a gap |
| Who can apply this code, and from where? | The weight of missing deletion protection and of secrets in state |

## Cost

| Question | What the answer changes |
|---|---|
| Can you share a recent bill, a cost export, or a pricing calculator result? | Whether any figure can be given at all. Without one, give none |
| Are there commitments in place (reserved capacity, savings plans, committed use)? | Whether a change in instance type or count would save or strand spend |
| What is the measured utilisation of the main compute and data resources? | Whether anything is over-provisioned. Instance type alone does not say |
| Which environments may be switched off outside working hours? | Whether always-on non-production resources are waste |

## If the user cannot answer

Continue with what does not depend on the answer. For what does, state the
assumption in the report, for example "assuming loss of one zone must be
survived", and list the findings whose severity would change if it is wrong.
Do not pick the assumption that makes the review look cleaner.
