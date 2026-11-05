#!/usr/bin/env python3
"""Inventory the infrastructure code in a repository and flag visible weaknesses.

Walks a directory for Terraform (.tf, .tfvars), CloudFormation templates
(JSON), and Kubernetes or Compose files (JSON, or YAML when PyYAML is
installed). Prints the resources by cloud and category, the findings from
iac_checks.py, and everything it could not evaluate.

It reads code, not cloud accounts. A resource that is absent here may exist
elsewhere, and a value set by a variable, a module or a dynamic block is
reported as "not evaluated", never guessed. Directories and files whose names
start with a dot, and node_modules, are not walked.

Examples:
  iac_inventory.py .                        # scan a repository
  iac_inventory.py infra/ --json            # machine-readable
  iac_inventory.py infra/ --fail-on medium  # exit 1 on medium findings too
  iac_inventory.py . --skip-yaml            # no PyYAML: list YAML files as not read
  iac_inventory.py --list-types             # every resource type the script knows

Exit codes: 0 = ran, no finding at or above --fail-on (default high);
1 = at least one such finding; 2 = usage or input error, including "no
infrastructure code found" and "YAML present but PyYAML missing".
Standard library only. Reads files only. Makes no network calls.
"""
import argparse
import json
import os
import sys

import iac_checks
import tf_reader
from iac_checks import Resource

CATEGORIES = ("compute", "data", "network", "identity", "observability")
MAX_BYTES = 5 * 1024 * 1024
CATALOG = {
    "aws": {
        "compute": "aws_instance aws_launch_template aws_autoscaling_group aws_ecs_cluster aws_ecs_service "
                   "aws_ecs_task_definition aws_eks_cluster aws_eks_node_group aws_lambda_function "
                   "AWS::EC2::Instance AWS::EC2::LaunchTemplate AWS::AutoScaling::AutoScalingGroup "
                   "AWS::ECS::Cluster AWS::ECS::Service AWS::ECS::TaskDefinition AWS::EKS::Cluster "
                   "AWS::EKS::Nodegroup AWS::Lambda::Function AWS::Serverless::Function",
        "data": "aws_db_instance aws_rds_cluster aws_rds_cluster_instance aws_dynamodb_table aws_s3_bucket "
                "aws_s3_bucket_acl aws_s3_bucket_public_access_block aws_s3_bucket_versioning "
                "aws_s3_bucket_server_side_encryption_configuration aws_s3_bucket_policy aws_ebs_volume "
                "aws_ebs_encryption_by_default aws_efs_file_system aws_elasticache_cluster "
                "aws_elasticache_replication_group aws_redshift_cluster aws_opensearch_domain "
                "AWS::RDS::DBInstance AWS::RDS::DBCluster AWS::DynamoDB::Table AWS::S3::Bucket "
                "AWS::S3::BucketPolicy AWS::EC2::Volume AWS::EFS::FileSystem AWS::ElastiCache::CacheCluster "
                "AWS::ElastiCache::ReplicationGroup AWS::Redshift::Cluster AWS::OpenSearchService::Domain",
        "network": "aws_vpc aws_subnet aws_security_group aws_security_group_rule "
                   "aws_vpc_security_group_ingress_rule aws_vpc_security_group_egress_rule aws_internet_gateway "
                   "aws_nat_gateway aws_route_table aws_eip aws_lb aws_alb aws_elb aws_lb_listener "
                   "aws_lb_target_group aws_cloudfront_distribution aws_route53_zone aws_route53_record "
                   "aws_api_gateway_rest_api aws_apigatewayv2_api "
                   "AWS::EC2::VPC AWS::EC2::Subnet AWS::EC2::SecurityGroup AWS::EC2::SecurityGroupIngress "
                   "AWS::EC2::InternetGateway AWS::EC2::NatGateway AWS::EC2::RouteTable AWS::EC2::EIP "
                   "AWS::ElasticLoadBalancingV2::LoadBalancer AWS::ElasticLoadBalancingV2::Listener "
                   "AWS::ElasticLoadBalancingV2::TargetGroup AWS::ElasticLoadBalancing::LoadBalancer "
                   "AWS::CloudFront::Distribution AWS::Route53::HostedZone AWS::Route53::RecordSet "
                   "AWS::ApiGateway::RestApi AWS::ApiGatewayV2::Api",
        "identity": "aws_iam_role aws_iam_policy aws_iam_role_policy aws_iam_role_policy_attachment aws_iam_user "
                    "aws_iam_access_key aws_iam_instance_profile aws_kms_key aws_secretsmanager_secret "
                    "aws_secretsmanager_secret_version aws_ssm_parameter "
                    "AWS::IAM::Role AWS::IAM::Policy AWS::IAM::ManagedPolicy AWS::IAM::User AWS::IAM::AccessKey "
                    "AWS::IAM::InstanceProfile AWS::KMS::Key AWS::SecretsManager::Secret AWS::SSM::Parameter",
        "observability": "aws_cloudwatch_metric_alarm aws_cloudwatch_log_group aws_cloudwatch_dashboard "
                         "aws_cloudtrail aws_flow_log AWS::CloudWatch::Alarm AWS::Logs::LogGroup "
                         "AWS::CloudWatch::Dashboard AWS::CloudTrail::Trail AWS::EC2::FlowLog",
    },
    "azure": {
        "compute": "azurerm_linux_virtual_machine azurerm_windows_virtual_machine "
                   "azurerm_linux_virtual_machine_scale_set azurerm_windows_virtual_machine_scale_set "
                   "azurerm_kubernetes_cluster azurerm_kubernetes_cluster_node_pool azurerm_service_plan "
                   "azurerm_linux_web_app azurerm_windows_web_app azurerm_linux_function_app "
                   "azurerm_windows_function_app azurerm_container_app azurerm_container_group",
        "data": "azurerm_storage_account azurerm_storage_container azurerm_managed_disk azurerm_mssql_server "
                "azurerm_mssql_database azurerm_mssql_firewall_rule azurerm_postgresql_flexible_server "
                "azurerm_postgresql_flexible_server_firewall_rule azurerm_mysql_flexible_server "
                "azurerm_mysql_flexible_server_firewall_rule azurerm_cosmosdb_account azurerm_redis_cache",
        "network": "azurerm_virtual_network azurerm_subnet azurerm_network_security_group "
                   "azurerm_network_security_rule azurerm_public_ip azurerm_lb azurerm_application_gateway "
                   "azurerm_nat_gateway azurerm_network_interface azurerm_dns_zone azurerm_private_endpoint "
                   "azurerm_firewall azurerm_cdn_frontdoor_profile",
        "identity": "azurerm_role_assignment azurerm_role_definition azurerm_user_assigned_identity "
                    "azurerm_key_vault azurerm_key_vault_secret azurerm_key_vault_key "
                    "azurerm_key_vault_access_policy",
        "observability": "azurerm_log_analytics_workspace azurerm_application_insights "
                         "azurerm_monitor_metric_alert azurerm_monitor_action_group "
                         "azurerm_monitor_diagnostic_setting azurerm_monitor_activity_log_alert",
    },
    "gcp": {
        "compute": "google_compute_instance google_compute_instance_template google_compute_instance_group_manager "
                   "google_compute_region_instance_group_manager google_compute_autoscaler "
                   "google_compute_region_autoscaler google_container_cluster google_container_node_pool "
                   "google_cloud_run_service google_cloud_run_v2_service google_cloudfunctions_function "
                   "google_cloudfunctions2_function",
        "data": "google_sql_database_instance google_sql_database google_sql_user google_storage_bucket "
                "google_storage_bucket_iam_member google_storage_bucket_iam_binding google_compute_disk "
                "google_redis_instance google_bigquery_dataset google_bigquery_table google_spanner_instance "
                "google_bigtable_instance google_firestore_database google_filestore_instance",
        "network": "google_compute_network google_compute_subnetwork google_compute_firewall google_compute_router "
                   "google_compute_router_nat google_compute_address google_compute_global_address "
                   "google_compute_forwarding_rule google_compute_global_forwarding_rule "
                   "google_compute_backend_service google_compute_url_map google_compute_target_https_proxy "
                   "google_dns_managed_zone google_dns_record_set",
        "identity": "google_service_account google_service_account_key google_project_iam_member "
                    "google_project_iam_binding google_kms_key_ring google_kms_crypto_key "
                    "google_secret_manager_secret google_secret_manager_secret_version",
        "observability": "google_monitoring_alert_policy google_monitoring_notification_channel "
                         "google_monitoring_uptime_check_config google_monitoring_dashboard google_logging_metric "
                         "google_logging_project_sink",
    },
    "kubernetes": {
        "compute": "Deployment StatefulSet DaemonSet Job CronJob Pod HorizontalPodAutoscaler PodDisruptionBudget",
        "data": "PersistentVolumeClaim PersistentVolume",
        "network": "Service Ingress NetworkPolicy",
        "identity": "ServiceAccount Role ClusterRole RoleBinding ClusterRoleBinding Secret",
        "observability": "ServiceMonitor PodMonitor PrometheusRule",
    },
    "compose": {"compute": "service"},
}
TYPE_INDEX = dict((rtype, (cloud, category)) for cloud, groups in CATALOG.items()
                  for category, names in groups.items() for rtype in names.split())
TF_PREFIXES = (("aws_", "aws"), ("azurerm_", "azure"), ("google_", "gcp"))
YAML_HELP = """iac_inventory.py: found %d YAML file(s), but PyYAML is not installed and this script
does not parse YAML itself. First of them: %s
Choose one:
  1. Install PyYAML (pip install pyyaml) and run again.
  2. Convert the files that matter to JSON and scan those:
       yq -o=json '.' deployment.yaml > deployment.json        (yq version 4)
       docker compose -f compose.yaml config --format json > compose.json
       cfn-flip template.yaml template.json                     (CloudFormation)
  3. Pass --skip-yaml to scan everything else. The YAML files are then listed
     as not read."""


class Scan(object):
    def __init__(self):
        self.resources = []      # Resource objects, declared or not
        self.files = {}          # terraform / cloudformation / kubernetes / compose -> files read
        self.not_read = []       # {"file", "reason"}
        self.unrecognised = 0    # JSON and YAML files that hold no infrastructure code
        self.other_blocks = {}   # Terraform block type -> count (variable, module, data, ...)

    def count(self, table, key):
        table[key] = table.get(key, 0) + 1

    def add(self, resource):
        resource.cloud, resource.category = classify(resource.source, resource.type, resource.cloud)
        self.resources.append(resource)


def classify(source, rtype, cloud):
    if rtype in TYPE_INDEX and (source == "terraform" or TYPE_INDEX[rtype][0] == cloud):
        return TYPE_INDEX[rtype]
    for prefix, name in TF_PREFIXES:
        if source == "terraform" and rtype.startswith(prefix):
            return name, "uncategorised"
    return cloud, "uncategorised"


def file_kind(name):
    lower = name.lower()
    for suffix, kind in ((".tf.json", "tfjson"), (".tf", "terraform"), (".tfvars", "tfvars"),
                         (".json", "json"), (".yaml", "yaml"), (".yml", "yaml")):
        if lower.endswith(suffix):
            return kind
    return None


def find_files(root, excludes):
    """Return sorted (relative path, kind) pairs for candidate files under root."""
    found = []
    for current, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if not d.startswith(".") and d not in excludes]
        for name in files:
            if file_kind(name) and not name.startswith("."):
                rel = os.path.relpath(os.path.join(current, name), root).replace(os.sep, "/")
                found.append((rel, file_kind(name)))
    return sorted(found)


def load_terraform(scan, rel, path, kind):
    try:
        root = tf_reader.read_file(path)
    except tf_reader.ReadError as exc:
        scan.not_read.append({"file": rel, "reason": "the Terraform reader stopped at %s" % exc})
        return
    scan.count(scan.files, "terraform")
    if kind == "tfvars":
        scan.add(Resource("terraform", "other", "tfvars", rel, "tfvars", rel, 1, root, declared=False))
        return
    for block in root.blocks:
        labels = block.labels
        if block.type == "resource" and len(labels) == 2:
            scan.add(Resource("terraform", "other", labels[0], labels[1], "%s.%s" % tuple(labels),
                              rel, block.line, block))
            continue
        scan.count(scan.other_blocks, block.type)
        if block.type in ("module", "provider", "variable") and labels:
            prefix = "var" if block.type == "variable" else block.type
            scan.add(Resource("terraform", "other", block.type, labels[0], "%s.%s" % (prefix, labels[0]),
                              rel, block.line, block, declared=False))
        elif block.type == "locals":
            scan.add(Resource("terraform", "other", "locals", "locals", "locals", rel, block.line, block,
                              declared=False))


def parse_json_documents(text):
    """Parse one JSON value, or several written one after another (as yq
    prints for a multi-document YAML file). Raises ValueError."""
    decoder, docs, pos = json.JSONDecoder(), [], 0
    while True:
        while pos < len(text) and text[pos].isspace():
            pos += 1
        if pos >= len(text):
            return docs
        doc, pos = decoder.raw_decode(text, pos)
        docs.append(doc)


def add_document(scan, rel, doc):
    """Add the resources in one JSON or YAML document. Return the kinds recognised."""
    if isinstance(doc, list):
        return set(kind for item in doc for kind in add_document(scan, rel, item))
    if not isinstance(doc, dict):
        return set()
    resources = doc.get("Resources")
    if isinstance(resources, dict) and ("AWSTemplateFormatVersion" in doc or any(
            isinstance(r, dict) and str(r.get("Type")).startswith(("AWS::", "Custom::"))
            for r in resources.values())):
        for name in sorted(resources, key=str):
            if isinstance(resources[name], dict) and isinstance(resources[name].get("Type"), str):
                scan.add(Resource("cloudformation", "aws", resources[name]["Type"], str(name),
                                  "Resources.%s" % name, rel, None, resources[name]))
        if isinstance(doc.get("Parameters"), dict):
            scan.add(Resource("cloudformation", "aws", "Parameters", "Parameters", "Parameters", rel, None,
                              doc["Parameters"], declared=False))
        return set(["cloudformation"])
    if isinstance(doc.get("apiVersion"), str) and isinstance(doc.get("kind"), str):
        if doc["kind"] == "List":
            return add_document(scan, rel, doc.get("items") or []) | set(["kubernetes"])
        meta = doc.get("metadata") if isinstance(doc.get("metadata"), dict) else {}
        name = str(meta.get("name", "(unnamed)"))
        scan.add(Resource("kubernetes", "kubernetes", doc["kind"], name, "%s/%s" % (doc["kind"], name),
                          rel, None, doc))
        return set(["kubernetes"])
    services = doc.get("services")
    if (isinstance(services, dict) and services and all(isinstance(s, dict) for s in services.values())
            and any("image" in s or "build" in s for s in services.values())):
        for name in sorted(services, key=str):
            scan.add(Resource("compose", "compose", "service", str(name), "services.%s" % name, rel, None,
                              services[name]))
        return set(["compose"])
    return set()


def load_documents(scan, rel, path, yaml_module):
    with open(path, encoding="utf-8", errors="replace") as handle:
        text = handle.read()
    try:
        if yaml_module is None:
            docs = parse_json_documents(text)
        else:
            docs = list(yaml_module.safe_load_all(text))
    except (ValueError,) if yaml_module is None else (ValueError, yaml_module.YAMLError):
        scan.not_read.append({"file": rel, "reason": "not valid JSON" if yaml_module is None else (
            "could not be parsed as YAML. Helm templates and CloudFormation short tags such as !Ref "
            "are not supported: render the chart with helm template, or convert the template with cfn-flip")})
        return
    kinds = add_document(scan, rel, docs)
    for kind in sorted(kinds):
        scan.count(scan.files, kind)
    if not kinds:
        scan.unrecognised += 1


def scan_files(root, files, yaml_module, skip_yaml):
    scan = Scan()
    for rel, kind in files:
        path = os.path.join(root, rel)
        try:
            if os.path.getsize(path) > MAX_BYTES:
                scan.not_read.append({"file": rel, "reason": "larger than %d MB" % (MAX_BYTES // 1048576)})
            elif kind == "tfjson":
                scan.not_read.append({"file": rel, "reason": "Terraform JSON syntax (.tf.json) is not supported"})
            elif kind == "yaml" and skip_yaml:
                scan.not_read.append({"file": rel, "reason": "YAML, skipped by --skip-yaml"})
            elif kind in ("terraform", "tfvars"):
                load_terraform(scan, rel, path, kind)
            else:
                load_documents(scan, rel, path, yaml_module if kind == "yaml" else None)
        except (IOError, OSError) as exc:
            scan.not_read.append({"file": rel, "reason": "cannot be opened: %s" % (exc.strerror or exc)})
        except RecursionError:
            scan.not_read.append({"file": rel, "reason": "nested too deeply to read"})
    return scan


def build_result(root, scan, fail_on):
    findings, not_evaluated = iac_checks.run_checks(scan.resources)
    declared = [res for res in scan.resources if res.declared]
    inventory = {}
    for res in declared:
        types = inventory.setdefault(res.cloud, {}).setdefault(res.category, {})
        types[res.type] = types.get(res.type, 0) + 1
    not_found = [{"cloud": cloud, "categories": [c for c in CATEGORIES if c not in inventory[cloud]]}
                 for cloud in ("aws", "azure", "gcp") if cloud in inventory]
    counts = dict((name, len([f for f in findings if f["severity"] == name])) for name in iac_checks.SEVERITIES)
    threshold = iac_checks.SEVERITIES.index(fail_on) if fail_on != "never" else len(iac_checks.SEVERITIES)
    blocking = len([f for f in findings if iac_checks.SEVERITIES.index(f["severity"]) >= threshold])
    return {
        "root": root, "files_read": scan.files, "files_not_read": scan.not_read,
        "files_without_infrastructure_code": scan.unrecognised,
        "terraform_blocks_not_inventoried": scan.other_blocks,
        "inventory": inventory,
        "resources": [{"address": r.address, "type": r.type, "cloud": r.cloud, "category": r.category,
                       "source": r.source, "file": r.file, "line": r.line} for r in declared],
        "findings": findings, "not_evaluated": not_evaluated,
        "not_found_in_code": [entry for entry in not_found if entry["categories"]],
        "summary": dict(counts, fail_on=fail_on, blocking=blocking),
    }


def _location(item):
    return "%s:%d" % (item["file"], item["line"]) if item["line"] else "%s: %s" % (item["file"], item["path"])


def _counted(table):
    return ", ".join("%s x%d" % pair for pair in sorted(table.items()))


def print_report(result):
    summary = result["summary"]
    print("Scanned %s: %s" % (result["root"], ", ".join(
        "%d %s file(s)" % (count, kind) for kind, count in sorted(result["files_read"].items()))))
    print("\nINVENTORY (%d resources)" % len(result["resources"]))
    for cloud in sorted(result["inventory"]):
        for category in CATEGORIES + ("uncategorised",):
            if category in result["inventory"][cloud]:
                print("  %-10s %-13s %s" % (cloud, category, _counted(result["inventory"][cloud][category])))
    if any("uncategorised" in groups for groups in result["inventory"].values()):
        print("  Types under 'uncategorised' are not in the script's catalogue: counted, not checked.")
    if result["terraform_blocks_not_inventoried"]:
        print("  Other Terraform blocks: %s" % _counted(result["terraform_blocks_not_inventoried"]))
    print("\nFINDINGS (%d high, %d medium, %d low)" % (summary["high"], summary["medium"], summary["low"]))
    for item in result["findings"]:
        print("  [%s] %s  %s  (%s)\n      %s" % (
            item["severity"], item["check"], item["resource"], _location(item), item["message"]))
    if result["not_evaluated"]:
        print("\nNOT EVALUATED (%d). The script did not guess these. Read the code or ask; "
              "they are neither findings nor passes." % len(result["not_evaluated"]))
        for item in result["not_evaluated"]:
            print("  %s  (%s)\n      %s" % (item["resource"], _location(item), item["detail"]))
    if result["not_found_in_code"]:
        print("\nNOT FOUND IN THE SCANNED CODE. This is not proof of absence in the cloud account; ask.")
        for entry in result["not_found_in_code"]:
            print("  %s: no %s resources" % (entry["cloud"], ", ".join(entry["categories"])))
    if result["files_not_read"]:
        print("\nFILES NOT READ (%d). The inventory is incomplete where these matter." % len(result["files_not_read"]))
        for entry in result["files_not_read"]:
            print("  %s: %s" % (entry["file"], entry["reason"]))
    open_items = ["%d %s" % (len(result[key]), label) for key, label in (
        ("not_evaluated", "item(s) not evaluated"), ("files_not_read", "file(s) not read")) if result[key]]
    print("\nRESULT: %d finding(s) at or above '%s'.%s" % (
        summary["blocking"], summary["fail_on"], " Still open: %s." % ", ".join(open_items) if open_items else ""))


def print_types(as_json):
    table = dict((cloud, dict((category, names.split()) for category, names in groups.items()))
                 for cloud, groups in CATALOG.items())
    if as_json:
        print(json.dumps(table, indent=2, sort_keys=True))
        return
    for cloud in sorted(table):
        for category in CATEGORIES:
            for rtype in table[cloud].get(category, []):
                print("%-10s %-13s %s" % (cloud, category, rtype))


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("path", nargs="?", help="repository, directory or single file to scan")
    parser.add_argument("--json", action="store_true", help="print JSON")
    parser.add_argument("--fail-on", choices=("high", "medium", "low", "never"), default="high",
                        help="lowest severity that makes the exit code 1 (default high)")
    parser.add_argument("--skip-yaml", action="store_true",
                        help="do not read YAML files; list them as not read")
    parser.add_argument("--exclude", action="append", default=[], metavar="DIR",
                        help="directory name to skip, as well as node_modules; repeatable")
    parser.add_argument("--list-types", action="store_true",
                        help="print the resource types the script knows, then exit")
    args = parser.parse_args(argv)
    if args.list_types:
        print_types(args.json)
        return 0
    if not args.path:
        parser.error("give a path to scan, or --list-types")
    if os.path.isdir(args.path):
        root, files = args.path, find_files(args.path, set(args.exclude + ["node_modules"]))
    elif os.path.isfile(args.path) and file_kind(os.path.basename(args.path)):
        root, files = os.path.dirname(args.path) or ".", [(os.path.basename(args.path), file_kind(args.path))]
    else:
        print("iac_inventory.py: %s is not a directory or a .tf, .tfvars, .json, .yaml or .yml file"
              % args.path, file=sys.stderr)
        return 2

    yaml_files = [rel for rel, kind in files if kind == "yaml"]
    yaml_module = None
    if yaml_files and not args.skip_yaml:
        try:
            import yaml as yaml_module
        except ImportError:
            print(YAML_HELP % (len(yaml_files), ", ".join(yaml_files[:5])), file=sys.stderr)
            return 2

    scan = scan_files(root, files, yaml_module, args.skip_yaml)
    if not scan.files:
        print("iac_inventory.py: no infrastructure code could be read under %s" % args.path, file=sys.stderr)
        for entry in scan.not_read:
            print("  not read: %s: %s" % (entry["file"], entry["reason"]), file=sys.stderr)
        return 2
    result = build_result(args.path, scan, args.fail_on)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print_report(result)
    return 1 if result["summary"]["blocking"] else 0


if __name__ == "__main__":
    sys.exit(main())
