#!/usr/bin/env python3
"""The checks that iac_inventory.py runs on the resources it finds.

A check reports a finding only when the weakness is visible in the code: a
literal value, or an attribute left unset whose documented provider default
is the weak setting. When the attribute is an expression (a variable, local,
function call), sits in a dynamic block, or is unset and this script is not
prepared to state its default, the check reports "not evaluated" instead.
It never guesses, and it never prints the value of a secret it flags.

Sections of this file, in order: check ids; attribute lookup shared by
Terraform blocks and JSON documents; the table of single-attribute rules;
firewall rules; checks that need more than one attribute; secrets; the runner.

Run this file to list every check with its severity, pillar and resource types:

Examples:
  iac_checks.py
  iac_checks.py --json

Exit codes: 0 = list printed, 2 = usage error. Exit code 1 is not used here;
findings come from iac_inventory.py.
Standard library only. Reads nothing. Makes no network calls.
"""
import argparse
import json
import re
import sys

from tf_reader import Unknown, brief

SET, UNSET, UNKNOWN = "set", "unset", "not evaluated"
NO_DEFAULT = object()  # unset: report "not evaluated" instead of assuming a default
FINE = object()        # unset is not a weakness
SEVERITIES = ("low", "medium", "high")

CHECKS = {  # id: (default severity, pillar, title)
    "public-database": ("high", "security", "Database reachable from the internet"),
    "db-open-to-azure-services": ("medium", "security", "Database firewall open to every Azure tenant"),
    "public-storage": ("high", "security", "Storage readable by anyone"),
    "public-access-block-disabled": ("medium", "security", "S3 public access block switched off"),
    "open-ingress": ("high", "security", "Firewall rule open to the internet (high for admin and "
                     "database ports or every port, medium for other ports, none for 80 and 443)"),
    "plaintext-secret": ("high", "security", "Secret written as a literal value"),
    "storage-not-encrypted": ("high", "security", "Storage not encrypted at rest (medium for disks and file systems)"),
    "insecure-transport": ("medium", "security", "Unencrypted or outdated transport allowed"),
    "db-backups-disabled": ("high", "reliability", "Automated database backups switched off"),
    "db-no-point-in-time-recovery": ("medium", "reliability", "No point-in-time recovery"),
    "db-single-zone": ("medium", "reliability", "Data store with no standby in another zone"),
    "no-deletion-protection": ("medium", "reliability", "No deletion protection"),
    "single-instance": ("low", "reliability", "Single instance with no scaling group"),
    "storage-not-zone-redundant": ("low", "reliability", "Storage kept in one datacentre"),
    "log-retention-unbounded": ("low", "cost", "Logs kept forever"),
}


class Resource(object):
    """One block or document found in infrastructure code."""

    def __init__(self, source, cloud, rtype, name, address, file, line, body, declared=True):
        self.source = source      # terraform, cloudformation, kubernetes or compose
        self.cloud, self.type, self.name, self.address = cloud, rtype, name, address
        self.file, self.line, self.body = file, line, body
        self.declared = declared  # False for providers, modules, variables, locals, tfvars, parameters
        self.category = "uncategorised"

    def get(self, path):
        return lookup(self.source, self.body, path)

    def where(self, path):
        """The path as printed: JSON sources get the full path from the document root."""
        return "%s.%s" % (self.address, path) if self.source in ("cloudformation", "compose") else path


def _intrinsic(value):
    return (isinstance(value, dict) and len(value) == 1
            and (list(value)[0] == "Ref" or list(value)[0].startswith("Fn::")))


def children(source, body, name):
    """Nested blocks called name, plus the reason if some cannot be read."""
    if source != "terraform":
        value = body.get(name)
        items = value if isinstance(value, list) else [value]
        why = "an intrinsic function" if source == "cloudformation" and any(
            _intrinsic(item) for item in items) else None
        return [item for item in items if isinstance(item, dict) and not (why and _intrinsic(item))], why
    why = None
    for child in body.blocks:
        if child.type == "dynamic" and child.labels[:1] == [name]:
            why = 'a dynamic "%s" block (line %d)' % (name, child.line)
    if name in body.attrs:
        why = "an attribute expression (%s = ...)" % name
    return [child for child in body.blocks if child.type == name], why


def _descend(source, body, parts):
    """Follow nested block names. Return (body, None), or (None, reason) when
    a block is absent (reason None) or cannot be read."""
    for part in parts:
        found, why = children(source, body, part)
        if not found:
            return None, why
        body = found[0]
    return body, None


def lookup(source, body, path):
    """Return (state, value, line) for a dotted attribute path under body.
    For the state UNKNOWN the value is a sentence saying why."""
    parts = path.split(".")
    body, why = _descend(source, body, parts[:-1])
    if body is None:
        return (UNKNOWN, "%s is inside %s" % (path, why), None) if why else (UNSET, None, None)
    if source == "terraform":
        attr = body.attrs.get(parts[-1])
        if attr is None or attr.value is None:
            return UNSET, None, attr.line if attr else None
        if isinstance(attr.value, Unknown):
            return UNKNOWN, "%s = %s" % (path, brief(attr.value.raw)), attr.line
        return SET, attr.value, attr.line
    value = body.get(parts[-1])
    if value is None:
        return UNSET, None, None
    if source == "cloudformation" and _intrinsic(value):
        return UNKNOWN, "%s = %s" % (path, brief(json.dumps(value, sort_keys=True, default=str))), None
    return SET, value, None


class Report(object):
    def __init__(self):
        self.findings, self.not_evaluated = [], []

    def add(self, check, res, path, message, line=None, severity=None):
        self.findings.append({
            "check": check, "severity": severity or CHECKS[check][0], "pillar": CHECKS[check][1],
            "cloud": res.cloud, "resource": res.address, "file": res.file,
            "line": line or res.line, "path": res.where(path), "message": message})

    def skip(self, check, res, path, detail, line=None):
        self.not_evaluated.append({
            "check": check, "resource": res.address, "file": res.file,
            "line": line or res.line, "path": res.where(path), "detail": detail})


def is_true(value):
    return value is True or (isinstance(value, str) and value.lower() == "true")


def is_false(value):
    return value is False or (isinstance(value, str) and value.lower() == "false")


def equals(number):
    def test(value):
        try:
            return not isinstance(value, bool) and float(value) == number
        except (TypeError, ValueError):
            return False
    return test


def one_of(*names):
    return lambda value: isinstance(value, str) and value.lower() in [n.lower() for n in names]


def show(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    return '"%s"' % value if isinstance(value, str) else str(value)


def _cluster_encryption_default(res, ctx):
    """Provider docs: false for provisioned clusters, true for engine_mode serverless."""
    state, mode, _ = res.get("engine_mode" if res.source == "terraform" else "Properties.EngineMode")
    if state == UNKNOWN:
        return NO_DEFAULT
    return FINE if state == SET and str(mode).lower() == "serverless" else False


def _ebs_default(res, ctx):
    """An aws_ebs_encryption_by_default resource in the scan covers unset volumes."""
    return FINE if "aws_ebs_encryption_by_default" in ctx["types"] else False


REPLICA = {"unless": ("replicate_source_db",)}
RESTORED = {"unless": ("replicate_source_db", "snapshot_identifier")}
CFN_REPLICA = {"unless": ("Properties.DBClusterIdentifier", "Properties.SourceDBInstanceIdentifier")}
CFN_RESTORED = {"unless": CFN_REPLICA["unless"] + ("Properties.DBSnapshotIdentifier",)}
SINGLE_ZONE = "The database has no standby in a second availability zone."
NO_BACKUPS = "Automated backups are switched off."
DB_PLAIN = "Database storage is not encrypted at rest."
DELETABLE = "Nothing stops this resource being deleted by one API call or one mistaken apply."
PUBLIC_DB = "The database is given a public address."
NO_PITR = "The table has no point-in-time recovery."
EBS_PLAIN = "The volume is not encrypted unless the account turns on EBS encryption by default."
EFS_PLAIN = "The file system is not encrypted at rest."
PUBLIC_ACL = "The ACL gives everyone on the internet access to the bucket."
LOGS_FOREVER = "Log events are kept forever, so the stored volume only grows."
ONE_MAX = "The group can never run more than one instance."
ONE_TASK = "The service runs one task."

RULES = [  # (check, resource types, attribute path, weak-value test, default when unset, meaning, options)
    # AWS, Terraform
    ("db-single-zone", "aws_db_instance", "multi_az", is_false, False, SINGLE_ZONE, REPLICA),
    ("db-backups-disabled", "aws_db_instance", "backup_retention_period", equals(0), NO_DEFAULT, NO_BACKUPS, REPLICA),
    ("storage-not-encrypted", "aws_db_instance", "storage_encrypted", is_false, False, DB_PLAIN, RESTORED),
    ("no-deletion-protection", "aws_db_instance aws_rds_cluster", "deletion_protection", is_false, False, DELETABLE),
    ("public-database", "aws_db_instance", "publicly_accessible", is_true, FINE, PUBLIC_DB),
    ("public-database", "aws_redshift_cluster", "publicly_accessible", is_true, NO_DEFAULT, PUBLIC_DB),
    ("storage-not-encrypted", "aws_rds_cluster", "storage_encrypted", is_false, _cluster_encryption_default,
     DB_PLAIN, {"unless": ("snapshot_identifier", "replication_source_identifier")}),
    ("db-no-point-in-time-recovery", "aws_dynamodb_table", "point_in_time_recovery.enabled", is_false, False, NO_PITR),
    ("no-deletion-protection", "aws_dynamodb_table", "deletion_protection_enabled", is_false, False, DELETABLE),
    ("storage-not-encrypted", "aws_ebs_volume", "encrypted", is_false, _ebs_default, EBS_PLAIN, {"severity": "medium"}),
    ("storage-not-encrypted", "aws_efs_file_system", "encrypted", is_false, False, EFS_PLAIN, {"severity": "medium"}),
    ("public-storage", "aws_s3_bucket aws_s3_bucket_acl", "acl", one_of("public-read", "public-read-write"), FINE, PUBLIC_ACL),
    ("single-instance", "aws_autoscaling_group", "max_size", equals(1), FINE, ONE_MAX),
    ("single-instance", "aws_ecs_service", "desired_count", equals(1), FINE, ONE_TASK),
    ("log-retention-unbounded", "aws_cloudwatch_log_group", "retention_in_days", equals(0), 0, LOGS_FOREVER,
     {"unset": "retention_in_days is not set"}),
    # AWS, CloudFormation
    ("db-single-zone", "AWS::RDS::DBInstance", "Properties.MultiAZ", is_false, False, SINGLE_ZONE, CFN_REPLICA),
    ("db-backups-disabled", "AWS::RDS::DBInstance", "Properties.BackupRetentionPeriod", equals(0), FINE, NO_BACKUPS),
    ("storage-not-encrypted", "AWS::RDS::DBInstance", "Properties.StorageEncrypted", is_false, False, DB_PLAIN, CFN_RESTORED),
    ("no-deletion-protection", "AWS::RDS::DBInstance", "Properties.DeletionProtection", is_false, False, DELETABLE,
     {"unless": ("Properties.DBClusterIdentifier",)}),
    ("no-deletion-protection", "AWS::RDS::DBCluster", "Properties.DeletionProtection", is_false, False, DELETABLE),
    ("public-database", "AWS::RDS::DBInstance AWS::Redshift::Cluster", "Properties.PubliclyAccessible", is_true, FINE, PUBLIC_DB),
    ("storage-not-encrypted", "AWS::RDS::DBCluster", "Properties.StorageEncrypted", is_false, _cluster_encryption_default,
     DB_PLAIN, {"unless": ("Properties.SnapshotIdentifier", "Properties.ReplicationSourceIdentifier")}),
    ("db-no-point-in-time-recovery", "AWS::DynamoDB::Table",
     "Properties.PointInTimeRecoverySpecification.PointInTimeRecoveryEnabled", is_false, False, NO_PITR),
    ("no-deletion-protection", "AWS::DynamoDB::Table", "Properties.DeletionProtectionEnabled", is_false, False, DELETABLE),
    ("storage-not-encrypted", "AWS::EC2::Volume", "Properties.Encrypted", is_false, False, EBS_PLAIN, {"severity": "medium"}),
    ("storage-not-encrypted", "AWS::EFS::FileSystem", "Properties.Encrypted", is_false, False, EFS_PLAIN, {"severity": "medium"}),
    ("public-storage", "AWS::S3::Bucket", "Properties.AccessControl", one_of("PublicRead", "PublicReadWrite"), FINE, PUBLIC_ACL),
    ("single-instance", "AWS::AutoScaling::AutoScalingGroup", "Properties.MaxSize", equals(1), FINE, ONE_MAX),
    ("single-instance", "AWS::ECS::Service", "Properties.DesiredCount", equals(1), FINE, ONE_TASK),
    ("log-retention-unbounded", "AWS::Logs::LogGroup", "Properties.RetentionInDays", equals(0), 0, LOGS_FOREVER,
     {"unset": "Properties.RetentionInDays is not set"}),
    # Azure, Terraform
    ("insecure-transport", "azurerm_storage_account", "https_traffic_only_enabled", is_false, FINE,
     "The storage account accepts unencrypted HTTP requests."),
    ("insecure-transport", "azurerm_storage_account", "enable_https_traffic_only", is_false, FINE,
     "The storage account accepts unencrypted HTTP requests."),
    ("insecure-transport", "azurerm_storage_account", "min_tls_version", one_of("TLS1_0", "TLS1_1"), FINE,
     "The storage account accepts TLS versions older than 1.2."),
    ("storage-not-zone-redundant", "azurerm_storage_account", "account_replication_type", one_of("LRS"), FINE,
     "Locally redundant storage keeps every copy in one datacentre."),
    ("public-storage", "azurerm_storage_container", "container_access_type", one_of("blob", "container"), FINE,
     "Anyone on the internet can read blobs in this container without signing in."),
    ("no-deletion-protection", "azurerm_key_vault", "purge_protection_enabled", is_false, False,
     "A deleted vault, key or secret can be purged before its retention period ends."),
    ("single-instance", "azurerm_linux_virtual_machine_scale_set azurerm_windows_virtual_machine_scale_set",
     "instances", equals(1), FINE, "The scale set runs one instance."),
    # Google Cloud, Terraform
    ("db-single-zone", "google_sql_database_instance", "settings.availability_type", one_of("ZONAL"), "ZONAL",
     "The instance runs in one zone with no standby.", {"unless": ("master_instance_name",)}),
    ("db-backups-disabled", "google_sql_database_instance", "settings.backup_configuration.enabled", is_false,
     NO_DEFAULT, NO_BACKUPS, {"unless": ("master_instance_name",)}),
    ("no-deletion-protection", "google_sql_database_instance", "deletion_protection", is_false, FINE,
     "Terraform is allowed to destroy this instance."),
    ("db-single-zone", "google_redis_instance", "tier", one_of("BASIC"), "BASIC",
     "Basic tier is a single node with no replica."),
    ("single-instance", "google_compute_instance_group_manager google_compute_region_instance_group_manager",
     "target_size", equals(1), FINE, "The group runs one instance."),
]


def _apply_rule(out, res, ctx, rule):
    check, _, path, weak, default, meaning = rule[:6]
    options = rule[6] if len(rule) > 6 else {}
    for other in options.get("unless", ()):
        if res.get(other)[0] != UNSET:
            out.skip(check, res, path, "%s is not checked because %s is set: for a replica, a restore "
                     "or a cluster member this is decided by the source or the cluster"
                     % (path, other.split(".")[-1]))
            return
    state, value, line = res.get(path)
    if state == UNKNOWN:
        out.skip(check, res, path, value, line)
        return
    seen = "%s = %s" % (path, show(value))
    if state == UNSET:
        value = default(res, ctx) if callable(default) else default
        if value is NO_DEFAULT:
            out.skip(check, res, path, "%s is not set, and this script does not assume a default for it" % path)
        if value is NO_DEFAULT or value is FINE:
            return
        seen = options.get("unset") or "%s is not set (documented default: %s)" % (path, show(value))
    if weak(value):
        out.add(check, res, path, "%s. %s" % (seen, meaning), line, options.get("severity"))


# --- firewall rules open to the internet ------------------------------------

WORLD = ("0.0.0.0/0", "::/0", "*", "internet")
ALL_PORTS = [(0, 65535)]
SENSITIVE_PORTS = {22: "SSH", 1433: "SQL Server", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
                   5432: "PostgreSQL", 6379: "Redis", 9200: "Elasticsearch", 11211: "Memcached",
                   27017: "MongoDB"}
PORT_PROTOCOLS = ("tcp", "udp", "6", "17", "-1", "all", "*")
TF_SG = (("cidr_blocks", "ipv6_cidr_blocks"), ("from_port", "to_port", "protocol"))
CFN_SG = (("CidrIp", "CidrIpv6"), ("FromPort", "ToPort", "IpProtocol"))


def _values(res, body, names):
    """Values of the named attributes, flattened. Expressions come back as Unknown."""
    found = []
    for name in names:
        state, value, _ = lookup(res.source, body, name)
        if state == UNKNOWN:
            found.append(Unknown(value))
        elif state == SET:
            found.extend(value if isinstance(value, list) else [value])
    return found


def _one(res, body, name):
    values = _values(res, body, [name])
    return values[0] if values else None


def _each(out, check, res, path):
    """Nested blocks at a dotted path. Reports the ones that cannot be read."""
    parts = path.split(".")
    body, why = _descend(res.source, res.body, parts[:-1])
    found, why = children(res.source, body, parts[-1]) if body is not None else ([], why)
    if why:
        out.skip(check, res, path, "%s is inside %s" % (path, why))
    return found


def _port_ranges(values):
    """(low, high) pairs for values such as 22, "22", "8000-8100" or "*".
    None if any value is not a literal port."""
    ranges = []
    for value in values:
        text = "" if isinstance(value, (bool, Unknown)) else str(value).strip()
        match = re.match(r"^(\d+)(?:\s*-\s*(\d+))?$", text)
        if text == "*":
            ranges.extend(ALL_PORTS)
        elif match:
            ranges.append((int(match.group(1)), int(match.group(2) or match.group(1))))
        else:
            return None
    return ranges or None


def _judge_ingress(out, res, path, line, sources, protocol, ranges):
    if isinstance(protocol, Unknown):
        protocol = None
    elif protocol is not None and str(protocol).lower() not in PORT_PROTOCOLS:
        return  # ICMP and other protocols without ports are not judged
    world = [s for s in sources if isinstance(s, str) and s.lower() in WORLD]
    if not world:
        if any(isinstance(s, Unknown) for s in sources):
            out.skip("open-ingress", res, path, "the source address range of this rule is an expression", line)
        return
    if ranges is None:
        out.skip("open-ingress", res, path,
                 "this rule allows %s, but its ports are not literal values" % world[0], line)
        return
    named = ["%d (%s)" % (port, SENSITIVE_PORTS[port]) for port in sorted(SENSITIVE_PORTS)
             if any(low <= port <= high for low, high in ranges)]
    if any(low <= 1 and high >= 65535 for low, high in ranges):
        what, severity = "every port", "high"
    elif named:
        what, severity = "port " + ", ".join(named), "high"
    elif all(low == high and low in (80, 443) for low, high in ranges):
        return
    else:
        what = "port " + ", ".join(str(low) if low == high else "%d-%d" % (low, high) for low, high in ranges)
        severity = "medium"
    out.add("open-ingress", res, path, "Inbound traffic from %s is allowed on %s." % (world[0], what), line, severity)


def _aws_rule(out, res, body, path, line, cidrs, names, prefix=""):
    protocol = _one(res, body, prefix + names[2])
    if not isinstance(protocol, Unknown) and str(protocol).lower() in ("-1", "all"):
        ranges = ALL_PORTS
    else:
        ends = _port_ranges(_values(res, body, [prefix + names[0]]) + _values(res, body, [prefix + names[1]]))
        ranges = [(ends[0][0], ends[1][1])] if ends and len(ends) == 2 else None
    _judge_ingress(out, res, path, line, _values(res, body, [prefix + c for c in cidrs]), protocol, ranges)


def _azure_rule(out, res, body, path, line):
    direction, access = _one(res, body, "direction"), _one(res, body, "access")
    if isinstance(direction, Unknown) or isinstance(access, Unknown):
        out.skip("open-ingress", res, path, "direction or access of this rule is an expression", line)
    elif str(direction).lower() == "inbound" and str(access).lower() == "allow":
        _judge_ingress(out, res, path, line,
                       _values(res, body, ["source_address_prefix", "source_address_prefixes"]),
                       _one(res, body, "protocol"),
                       _port_ranges(_values(res, body, ["destination_port_range", "destination_port_ranges"])))


def _open_ingress(out, res, ctx):
    kind = res.type
    if kind == "aws_security_group":
        for block in _each(out, "open-ingress", res, "ingress"):
            _aws_rule(out, res, block, "ingress", block.line, *TF_SG)
    elif kind == "aws_security_group_rule":
        direction = _one(res, res.body, "type")
        if isinstance(direction, Unknown):
            out.skip("open-ingress", res, "type", direction.raw)
        elif direction == "ingress":
            _aws_rule(out, res, res.body, "cidr_blocks", res.line, *TF_SG)
    elif kind == "aws_vpc_security_group_ingress_rule":
        _aws_rule(out, res, res.body, "cidr_ipv4", res.line, ("cidr_ipv4", "cidr_ipv6"),
                  ("from_port", "to_port", "ip_protocol"))
    elif kind == "AWS::EC2::SecurityGroup":
        for index, rule in enumerate(_each(out, "open-ingress", res, "Properties.SecurityGroupIngress")):
            _aws_rule(out, res, rule, "Properties.SecurityGroupIngress[%d]" % index, None, *CFN_SG)
    elif kind == "AWS::EC2::SecurityGroupIngress":
        _aws_rule(out, res, res.body, "Properties", None, *CFN_SG, prefix="Properties.")
    elif kind == "azurerm_network_security_group":
        for block in _each(out, "open-ingress", res, "security_rule"):
            _azure_rule(out, res, block, "security_rule", block.line)
    elif kind == "azurerm_network_security_rule":
        _azure_rule(out, res, res.body, "source_address_prefix", res.line)
    elif kind == "google_compute_firewall":
        direction = _one(res, res.body, "direction")
        if isinstance(direction, Unknown):
            out.skip("open-ingress", res, "direction", direction.raw)
        elif _one(res, res.body, "disabled") is not True and str(direction or "INGRESS").upper() == "INGRESS":
            sources = _values(res, res.body, ["source_ranges"])
            for block in _each(out, "open-ingress", res, "allow"):
                ports = _values(res, block, ["ports"])
                _judge_ingress(out, res, "allow", block.line, sources, _one(res, block, "protocol"),
                               _port_ranges(ports) if ports else ALL_PORTS)


# --- other checks that need more than one attribute --------------------------

PAB = ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets")
CFN_PAB = ("BlockPublicAcls", "BlockPublicPolicy", "IgnorePublicAcls", "RestrictPublicBuckets")


def _public_access_block(out, res, ctx):
    terraform = res.source == "terraform"
    prefix = "" if terraform else "Properties.PublicAccessBlockConfiguration."
    off = []
    for name in (PAB if terraform else CFN_PAB):
        state, value, line = res.get(prefix + name)
        if state == UNKNOWN:
            out.skip("public-access-block-disabled", res, prefix + name, value, line)
        elif (state == SET and is_false(value)) or (state == UNSET and terraform):
            off.append(name)  # Terraform documents false as the default; CloudFormation is judged only when explicit
    if off:
        out.add("public-access-block-disabled", res, prefix + off[0],
                "Not switched on: %s. This leaves public ACLs or public bucket policies possible." % ", ".join(off))


def _azure_db_firewall(out, res, ctx):
    start, end = _one(res, res.body, "start_ip_address"), _one(res, res.body, "end_ip_address")
    if isinstance(start, Unknown) or isinstance(end, Unknown):
        out.skip("public-database", res, "start_ip_address", "the address range of this firewall rule is an expression")
    elif (start, end) == ("0.0.0.0", "255.255.255.255"):
        out.add("public-database", res, "start_ip_address",
                "The firewall rule 0.0.0.0 to 255.255.255.255 admits every internet address.")
    elif (start, end) == ("0.0.0.0", "0.0.0.0"):
        out.add("db-open-to-azure-services", res, "start_ip_address",
                "The firewall rule 0.0.0.0 to 0.0.0.0 admits connections from all Azure services, "
                "including those in other customers' subscriptions.")


def _gcp_sql_networks(out, res, ctx):
    for block in _each(out, "public-database", res, "settings.ip_configuration.authorized_networks"):
        value = _one(res, block, "value")
        if isinstance(value, Unknown):
            out.skip("public-database", res, "settings.ip_configuration.authorized_networks", value.raw, block.line)
        elif value in ("0.0.0.0/0", "::/0"):
            out.add("public-database", res, "settings.ip_configuration.authorized_networks",
                    "authorized_networks value = %s. Every internet address may connect." % show(value), block.line)


NAMED_MEMBER_RE = re.compile(r'"(serviceAccount|user|group|domain):')  # a named principal, so not public


def _gcp_bucket_iam(out, res, ctx):
    path = "member" if res.type.endswith("_member") else "members"
    members = _values(res, res.body, [path])
    public = [m for m in members if m in ("allUsers", "allAuthenticatedUsers")]
    if public:
        out.add("public-storage", res, path, "%s includes %s. The role is granted to anyone on the internet."
                % (path, show(public[0])), res.get(path)[2])
    elif any(isinstance(m, Unknown) and not NAMED_MEMBER_RE.search(m.raw) for m in members):
        out.skip("public-storage", res, path, "%s is an expression" % path)


def _single_instance(out, res, ctx):
    if res.source == "terraform":
        for meta in ("count", "for_each"):
            state, value, line = res.get(meta)
            if state == UNKNOWN:
                out.skip("single-instance", res, meta, value, line)
                return
            if state == SET and (len(value) if isinstance(value, (list, dict)) else value) != 1:
                return  # none, or more than one
    out.add("single-instance", res, "count" if res.source == "terraform" else "Type",
            "Declared as one instance outside a scaling group. Nothing in this code replaces it if it fails.")


def _flexible_server_ha(out, res, ctx):
    blocks = _each(out, "db-single-zone", res, "high_availability")
    if not blocks and not children(res.source, res.body, "high_availability")[1]:
        out.add("db-single-zone", res, "high_availability", "No high_availability block. The server has no standby.")
    for block in blocks:
        if str(_one(res, block, "mode")).lower() == "samezone":
            out.add("db-single-zone", res, "high_availability.mode",
                    'mode = "SameZone". The standby is in the same zone as the primary.', block.line, "low")


def _k8s_replicas(out, res, ctx):
    spec = res.body.get("spec")
    replicas = spec.get("replicas", 1) if isinstance(spec, dict) else 1
    if replicas == 1 and (res.type, res.name) not in ctx["autoscaled"]:
        out.add("single-instance", res, "spec.replicas",
                "One replica (1 is also the default when spec.replicas is not set), and no "
                "HorizontalPodAutoscaler in the scanned files targets this workload.")


def _k8s_secret(out, res, ctx):
    keys = sorted(str(key) for part in ("data", "stringData")
                  for key in (res.body.get(part) or {}) if isinstance(res.body.get(part), dict))
    if keys and "sops" not in res.body:
        out.add("plaintext-secret", res, "data", "Secret manifest with values for %s is stored in the "
                "repository (values not shown). Base64 in data is an encoding, not encryption." % ", ".join(keys))


SPECIAL = [  # (check ids, resource types, function)
    ("open-ingress", "aws_security_group aws_security_group_rule aws_vpc_security_group_ingress_rule "
     "AWS::EC2::SecurityGroup AWS::EC2::SecurityGroupIngress azurerm_network_security_group "
     "azurerm_network_security_rule google_compute_firewall", _open_ingress),
    ("public-access-block-disabled", "aws_s3_bucket_public_access_block AWS::S3::Bucket", _public_access_block),
    ("public-database db-open-to-azure-services", "azurerm_mssql_firewall_rule "
     "azurerm_postgresql_flexible_server_firewall_rule azurerm_mysql_flexible_server_firewall_rule",
     _azure_db_firewall),
    ("public-database", "google_sql_database_instance", _gcp_sql_networks),
    ("public-storage", "google_storage_bucket_iam_member google_storage_bucket_iam_binding", _gcp_bucket_iam),
    ("single-instance", "aws_instance AWS::EC2::Instance azurerm_linux_virtual_machine "
     "azurerm_windows_virtual_machine google_compute_instance", _single_instance),
    ("db-single-zone", "azurerm_postgresql_flexible_server azurerm_mysql_flexible_server", _flexible_server_ha),
    ("single-instance", "Deployment StatefulSet", _k8s_replicas),
    ("plaintext-secret", "Secret", _k8s_secret),
]

# --- secrets written as literal values ----------------------------------------

SECRET_SUFFIXES = ("password", "passwd", "secret", "token", "api_key", "apikey", "access_key",
                   "accesskey", "secret_key", "secretkey", "private_key", "privatekey")
NOT_SECRET_NAMES = ("secret", "token", "servicetoken")  # names of references, not of values
SECRET_ATTRIBUTES = {  # attributes that hold a secret whatever they are called
    "aws_secretsmanager_secret_version": "secret_string",
    "azurerm_key_vault_secret": "value",
    "google_secret_manager_secret_version": "secret_data",
    "AWS::SecretsManager::Secret": "Properties.SecretString",
}
SECRET_SCOPE = ("every Terraform resource, provider, module, locals and variable block, .tfvars files, "
                "CloudFormation resources and parameters, Kubernetes documents and Compose services")


def looks_secret(name):
    name = str(name).lower().replace("-", "_")
    return name.endswith(SECRET_SUFFIXES) and name not in NOT_SECRET_NAMES


def _literal_secret(value):
    """A non-empty literal string that is not a variable or dynamic reference."""
    return isinstance(value, str) and bool(value.strip()) and not value.startswith(("$", "{{resolve:"))


def _secret_hits(name, value, path):
    """Yield (path, name) for secret-looking names that hold a literal string."""
    if isinstance(value, dict):
        pair_name = value.get("name", value.get("Name"))  # env entries: {name: X, value: Y}
        if looks_secret(pair_name) and _literal_secret(value.get("value", value.get("Value"))):
            yield (path + "." if path else "") + "value", pair_name
        for key in sorted(value, key=str):
            for hit in _secret_hits(key, value[key], "%s.%s" % (path, key) if path else str(key)):
                yield hit
    elif isinstance(value, list):
        for index, item in enumerate(value):
            if isinstance(item, str) and name == "environment" and "=" in item:  # Compose list form
                key, _, text = item.partition("=")
                if looks_secret(key) and _literal_secret(text):
                    yield "%s.%s" % (path, key), key
            for hit in _secret_hits(name, item, "%s[%d]" % (path, index)) if isinstance(item, (dict, list)) else ():
                yield hit
    elif looks_secret(name) and _literal_secret(value):
        yield path, name


def _block_hits(block, prefix):
    pair = block.attrs.get("name"), block.attrs.get("value")  # env blocks: name = X, value = Y
    if all(pair) and looks_secret(pair[0].value) and _literal_secret(pair[1].value):
        yield prefix + "value", pair[0].value, pair[1].line
    for name in sorted(block.attrs):
        for path, label in _secret_hits(name, block.attrs[name].value, prefix + name):
            yield path, label, block.attrs[name].line
    for child in block.blocks:
        for hit in _block_hits(child, prefix + child.type + "."):
            yield hit


def _plaintext_secrets(out, res):
    hits = []
    if res.source == "terraform" and res.type == "variable":
        state, value, line = res.get("default")
        if looks_secret(res.name) and state == SET and _literal_secret(value):
            hits.append(("default", res.name, line))
    elif res.source == "terraform":
        hits = list(_block_hits(res.body, ""))
    elif res.type == "Parameters" and not res.declared:
        hits = [("%s.Default" % name, name, None) for name in sorted(res.body)
                if looks_secret(name) and isinstance(res.body[name], dict)
                and _literal_secret(res.body[name].get("Default"))]
    elif not (res.source == "kubernetes" and res.type == "Secret"):
        hits = [(path, label, None) for path, label in _secret_hits("", res.body, "")]
    path = SECRET_ATTRIBUTES.get(res.type)
    if res.type == "aws_ssm_parameter" and res.get("type")[:2] == (SET, "SecureString"):
        path = "value"
    if path and res.get(path)[0] == SET and _literal_secret(res.get(path)[1]):
        hits.append((path, path.split(".")[-1], res.get(path)[2]))
    for path, label, line in sorted(set(hits), key=lambda hit: (hit[0], hit[1])):
        out.add("plaintext-secret", res, path, "%s is written as a literal value in this file (value not "
                "shown). Keep it in a secret store and reference it." % label, line)


def _index(table, position):
    index = {}
    for entry in table:
        for rtype in entry[1].split():
            index.setdefault(rtype, []).append(entry[position] if position is not None else entry)
    return index


RULE_INDEX = _index(RULES, None)
SPECIAL_INDEX = _index(SPECIAL, 2)


def run_checks(resources):
    """Return (findings, not_evaluated) for a list of Resource objects, sorted."""
    out = Report()
    ctx = {"types": set(res.type for res in resources if res.declared), "autoscaled": set()}
    for res in resources:
        spec = res.body.get("spec") if res.type == "HorizontalPodAutoscaler" else None
        target = spec.get("scaleTargetRef") if isinstance(spec, dict) else None
        if isinstance(target, dict):
            ctx["autoscaled"].add((target.get("kind"), target.get("name")))
    for res in resources:
        if res.declared:
            for rule in RULE_INDEX.get(res.type, ()):
                _apply_rule(out, res, ctx, rule)
            for function in SPECIAL_INDEX.get(res.type, ()):
                function(out, res, ctx)
        elif res.source == "terraform" and res.type == "module":
            state, value, _ = res.get("source")
            out.skip("module", res, "source", "source = %s. Resources created inside a module are not in "
                     "this inventory, and module inputs are not resolved."
                     % (show(value) if state == SET else "(not a literal)"))
        _plaintext_secrets(out, res)
    rank = dict((name, -index) for index, name in enumerate(SEVERITIES))
    out.findings.sort(key=lambda f: (rank[f["severity"]], f["file"], f["line"] or 0, f["resource"], f["check"], f["path"]))
    out.not_evaluated.sort(key=lambda n: (n["file"], n["line"] or 0, n["resource"], n["path"], n["check"]))
    return out.findings, out.not_evaluated


def list_checks():
    """Every check with the resource types it reads."""
    types = dict((check, set()) for check in CHECKS)
    for rule in RULES:
        types[rule[0]].update(rule[1].split())
    for checks, rtypes, _ in SPECIAL:
        for check in checks.split():
            types[check].update(rtypes.split())
    return [{"check": check, "severity": CHECKS[check][0], "pillar": CHECKS[check][1],
             "title": CHECKS[check][2], "resource_types": sorted(types[check]),
             "also": SECRET_SCOPE if check == "plaintext-secret" else None} for check in sorted(CHECKS)]


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--json", action="store_true", help="print JSON")
    args = parser.parse_args(argv)
    checks = list_checks()
    if args.json:
        print(json.dumps(checks, indent=2))
        return 0
    for entry in checks:
        print("%s  [%s, %s]\n    %s" % (entry["check"], entry["severity"], entry["pillar"], entry["title"]))
        for rtype in entry["resource_types"]:
            print("    - " + rtype)
        if entry["also"]:
            print("    - any attribute with a secret-like name in " + entry["also"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
