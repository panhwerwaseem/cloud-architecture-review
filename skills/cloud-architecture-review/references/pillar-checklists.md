# Pillar checklists

What to review under each pillar once `scripts/iac_inventory.py` has run.
Each section lists what the script already checked, then what only a reader
can check. Everything added by reading must still cite a file and a resource.

The script's checks are listed exactly in `known-types-and-checks.md`. The
questions referred to here are in `questions-to-ask.md`.

## Contents

- [Reliability](#reliability)
- [Security](#security)
- [Cost](#cost)
- [When pillars pull against each other](#when-pillars-pull-against-each-other)

## Reliability

**Already checked by the script:** `db-single-zone`, `db-backups-disabled`,
`db-no-point-in-time-recovery`, `no-deletion-protection`, `single-instance`,
`storage-not-zone-redundant`.

**Review by reading the code:**

| Look at | What to establish |
|---|---|
| Each tier in the inventory (entry point, compute, data, queues) | How many instances, in how many zones. One of anything on the request path is a single point of failure |
| Subnet and zone arguments | Whether compute and data are spread over at least two zones, or all placed in one |
| Scaling groups, node pools, replica counts | Minimum size. A minimum of one heals itself but has an outage while it does |
| Load balancer and target health checks | That unhealthy instances are detected and taken out of rotation |
| Backup settings on every data store | Retention period, and whether copies leave the zone or region the store is in |
| Stateful virtual machines | Data kept on a single instance's disk with no replica or snapshot schedule |
| Alarms and alert policies in the inventory | Whether the data stores and entry points have any. If none are in the code, ask where alerting is managed |
| The Terraform `backend` block | Remote state with locking. Local state lets two applies collide |

**Judge only against stated targets.** A single zone is a fact. Whether it is
a defect depends on the recovery time objective and on which failures the
system is meant to survive: an instance, a zone, or a region. Backup
retention is acceptable or not relative to the recovery point objective.
Without those numbers, report the fact and the failure it exposes the system
to.

**The code cannot show:** whether a restore has ever been tested, how
failover behaves in practice, or what the application does when a dependency
is slow. Ask.

## Security

**Already checked by the script:** `public-database`,
`db-open-to-azure-services`, `public-storage`, `public-access-block-disabled`,
`open-ingress`, `plaintext-secret`, `storage-not-encrypted`,
`insecure-transport`.

**Review by reading the code:**

| Look at | What to establish |
|---|---|
| IAM policies, role assignments, IAM bindings | Wildcard actions on wildcard resources; broad built-in roles (administrator, owner, editor, contributor) granted to workloads; trust policies that let any principal assume a role |
| Long-lived credentials created in code | Access keys and service account keys. Their secrets end up in Terraform state |
| Network placement of data stores | Private subnets or private endpoints, and which security groups or firewall rules can reach them |
| Public addresses on compute | Instances with public IPs that sit behind a load balancer anyway |
| Listeners and endpoints | Plain HTTP listeners without a redirect, and the minimum TLS version where it is configurable |
| How secrets reach workloads | A secret store referenced at run time, as opposed to a value passed through a variable into an environment block |
| Terraform state | State files hold resource attributes, including secrets, in plain text. Check that the backend is remote, encrypted and access-controlled |
| Audit logging | Whether an audit trail and flow logs are declared. If not in the code, ask: they are often set for the whole organisation |
| Encryption keys | Whether customer-managed keys are used where the data classification requires them |

**The script's secret check is name-based.** It finds `password = "..."`. It
does not find a key pasted into a user-data script, a heredoc or a
`jsonencode(...)` call. Read those by hand, and recommend a dedicated secret
scanner for the repository history.

**Severity depends on the data.** Ask for the data classification before
ranking. Public read access to a bucket of published assets is intended;
the same setting on customer documents is an incident.

**The code cannot show:** account-level and organisation-level controls,
who holds which role in the identity provider, or whether keys are rotated.
Ask.

## Cost

**Already checked by the script:** `log-retention-unbounded`. The inventory
itself is the main input: it lists what runs.

**Review by reading the code, structurally:**

| Look at | What to establish |
|---|---|
| Resources that bill while idle | Instances, provisioned databases, NAT gateways, load balancers, provisioned throughput. List them from the inventory |
| Fixed capacity where load varies | Compute with no scaling group, scaling groups whose minimum equals their maximum |
| Non-production environments | Whether they use production-sized values. Compare the `.tfvars` files |
| Storage that only grows | Buckets with no lifecycle rule, logs with no retention, snapshots with no expiry |
| Redundancy beyond the stated targets | Multi-region or large standby capacity for a system with relaxed recovery objectives |
| Tags and labels | Whether resources carry an owner or cost-centre tag, so spend can be attributed |
| Traffic paths | Cross-zone, cross-region and NAT-routed traffic between chatty components |

**No figures.** Do not state prices, monthly totals or percentage savings
unless the user has supplied a bill, a pricing export or a calculator result,
and then name that source next to every figure. Prices differ by region,
commitment and negotiated rate, and they change. Say what direction a change
moves cost in and what it trades away.

**The code cannot show:** utilisation. Whether an instance is too large
depends on measured load, not on its type. Ask for utilisation data before
calling anything over-provisioned.

## When pillars pull against each other

Most reliability and security improvements add cost, and most cost
reductions remove redundancy. Do not resolve the trade-off silently. Present
it with the target that decides it:

- A standby in a second zone removes a single point of failure and adds a
  second always-on instance. The recovery time objective decides.
- Longer backup retention lowers the risk of unrecoverable loss and adds
  stored volume. The recovery point objective and any retention rule decide.
- Private networking for a data store removes internet exposure and may add
  endpoints or gateways. The data classification decides.

If the targets are unknown, give the options and what each assumes.
