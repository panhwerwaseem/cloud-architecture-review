import json
import unittest

from support import TempTree, run

import iac_checks  # noqa: E402  (support puts the scripts directory on sys.path)
import iac_inventory  # noqa: E402

DB = 'resource "aws_db_instance" "db" {\n  storage_encrypted = true\n  deletion_protection = true\n%s}\n'
SG = 'resource "aws_security_group" "sg" {\n  ingress {\n%s  }\n}\n'


def cfn(resources, parameters=None):
    template = {"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources}
    if parameters:
        template["Parameters"] = parameters
    return template


class SingleAttributeRuleTests(TempTree, unittest.TestCase):
    def test_literal_weak_value_is_a_finding(self):
        self.assertEqual(self.checks({"main.tf": DB % "  multi_az = false\n  backup_retention_period = 7\n"}),
                         ["db-single-zone aws_db_instance.db"])

    def test_unset_attribute_with_a_documented_default_is_a_finding_that_says_so(self):
        result = self.scan_tree({"main.tf": DB % "  backup_retention_period = 7\n"})
        self.assertEqual([f["check"] for f in result["findings"]], ["db-single-zone"])
        self.assertIn("multi_az is not set (documented default: false)", result["findings"][0]["message"])

    def test_variable_is_reported_as_not_evaluated_never_as_a_finding_or_a_pass(self):
        files = {"main.tf": DB % "  multi_az = var.multi_az\n  backup_retention_period = 7\n",
                 "variables.tf": 'variable "multi_az" {\n  default = false\n}\n'}
        result = self.scan_tree(files)
        self.assertEqual(result["findings"], [])
        self.assertEqual([(n["check"], n["detail"]) for n in result["not_evaluated"]],
                         [("db-single-zone", "multi_az = var.multi_az")])

    def test_unset_attribute_without_a_stated_default_is_not_evaluated(self):
        files = {"main.tf": DB % "  multi_az = true\n"}
        self.assertEqual(self.checks(files), [])
        self.assertEqual(self.skipped(files), ["db-backups-disabled aws_db_instance.db"])

    def test_null_counts_as_unset(self):
        self.assertEqual(self.checks({"main.tf": DB % "  multi_az = null\n  backup_retention_period = 7\n"}),
                         ["db-single-zone aws_db_instance.db"])

    def test_replica_is_not_judged_on_settings_its_source_decides(self):
        files = {"main.tf": 'resource "aws_db_instance" "replica" {\n'
                            '  replicate_source_db = aws_db_instance.db.identifier\n  deletion_protection = true\n}\n'}
        self.assertEqual(self.checks(files), [])
        self.assertEqual(self.skipped(files), ["db-backups-disabled aws_db_instance.replica",
                                               "db-single-zone aws_db_instance.replica",
                                               "storage-not-encrypted aws_db_instance.replica"])

    def test_cluster_encryption_default_depends_on_engine_mode(self):
        cluster = 'resource "aws_rds_cluster" "c" {\n  deletion_protection = true\n%s}\n'
        self.assertEqual(self.checks({"main.tf": cluster % ""}), ["storage-not-encrypted aws_rds_cluster.c"])
        self.assertEqual(self.checks({"main.tf": cluster % '  engine_mode = "serverless"\n'}), [])
        files = {"main.tf": cluster % "  engine_mode = var.mode\n"}
        self.assertEqual(self.checks(files), [])
        self.assertEqual(self.skipped(files), ["storage-not-encrypted aws_rds_cluster.c"])

    def test_ebs_volume_is_not_flagged_when_account_default_encryption_is_in_the_code(self):
        volume = 'resource "aws_ebs_volume" "v" {\n  size = 10\n}\n'
        self.assertEqual(self.checks({"main.tf": volume}), ["storage-not-encrypted aws_ebs_volume.v"])
        self.assertEqual(self.checks({"main.tf": volume + 'resource "aws_ebs_encryption_by_default" "on" {\n}\n'}), [])

    def test_nested_block_path_and_dynamic_block(self):
        sql = 'resource "google_sql_database_instance" "db" {\n%s}\n'
        self.assertEqual(self.checks({"main.tf": sql % '  settings {\n    availability_type = "REGIONAL"\n'
                                      '    backup_configuration {\n      enabled = true\n    }\n  }\n'}), [])
        files = {"main.tf": sql % '  dynamic "settings" {\n    for_each = var.s\n    content {\n    }\n  }\n'}
        self.assertEqual(self.checks(files), [])
        self.assertEqual(self.skipped(files), ["db-backups-disabled google_sql_database_instance.db",
                                               "db-single-zone google_sql_database_instance.db",
                                               "public-database google_sql_database_instance.db"])

    def test_cloudformation_strings_for_booleans_and_numbers(self):
        files = {"t.json": cfn({"Db": {"Type": "AWS::RDS::DBInstance", "Properties": {
            "MultiAZ": "false", "StorageEncrypted": "true", "DeletionProtection": True,
            "BackupRetentionPeriod": "0"}}})}
        self.assertEqual(self.checks(files), ["db-backups-disabled Resources.Db", "db-single-zone Resources.Db"])

    def test_cloudformation_intrinsic_function_is_not_evaluated(self):
        files = {"t.json": cfn({"Db": {"Type": "AWS::RDS::DBInstance", "Properties": {
            "MultiAZ": {"Fn::If": ["Prod", True, False]}, "StorageEncrypted": True, "DeletionProtection": True}}})}
        self.assertEqual(self.checks(files), [])
        self.assertEqual(self.skipped(files), ["db-single-zone Resources.Db"])

    def test_severity_override_for_disks(self):
        result = self.scan_tree({"main.tf": 'resource "aws_efs_file_system" "fs" {\n}\n'})
        self.assertEqual([(f["check"], f["severity"]) for f in result["findings"]],
                         [("storage-not-encrypted", "medium")])


class OpenIngressTests(TempTree, unittest.TestCase):
    def ingress(self, body):
        result = self.scan_tree({"main.tf": SG % body})
        return [(f["severity"], f["message"]) for f in result["findings"]], result["not_evaluated"]

    def test_web_ports_open_to_the_world_are_not_findings(self):
        body = '    from_port = 443\n    to_port = 443\n    protocol = "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n'
        self.assertEqual(self.ingress(body), ([], []))

    def test_admin_port_open_to_the_world_is_high(self):
        body = '    from_port = 22\n    to_port = 22\n    protocol = "tcp"\n    cidr_blocks = ["10.0.0.0/8", "0.0.0.0/0"]\n'
        self.assertEqual(self.ingress(body)[0],
                         [("high", "Inbound traffic from 0.0.0.0/0 is allowed on port 22 (SSH).")])

    def test_range_covering_a_database_port_is_high(self):
        body = '    from_port = 5000\n    to_port = 6000\n    protocol = "tcp"\n    ipv6_cidr_blocks = ["::/0"]\n'
        self.assertEqual(self.ingress(body)[0],
                         [("high", "Inbound traffic from ::/0 is allowed on port 5432 (PostgreSQL).")])

    def test_all_protocols_is_every_port(self):
        body = '    from_port = 0\n    to_port = 0\n    protocol = "-1"\n    cidr_blocks = ["0.0.0.0/0"]\n'
        self.assertEqual(self.ingress(body)[0],
                         [("high", "Inbound traffic from 0.0.0.0/0 is allowed on every port.")])

    def test_other_port_is_medium(self):
        body = '    from_port = 8080\n    to_port = 8081\n    protocol = "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n'
        self.assertEqual(self.ingress(body)[0],
                         [("medium", "Inbound traffic from 0.0.0.0/0 is allowed on port 8080-8081.")])

    def test_private_source_and_icmp_are_not_findings(self):
        private = '    from_port = 22\n    to_port = 22\n    protocol = "tcp"\n    cidr_blocks = ["10.0.0.0/8"]\n'
        icmp = '    from_port = -1\n    to_port = -1\n    protocol = "icmp"\n    cidr_blocks = ["0.0.0.0/0"]\n'
        self.assertEqual(self.ingress(private), ([], []))
        self.assertEqual(self.ingress(icmp), ([], []))

    def test_variable_source_is_not_evaluated(self):
        body = '    from_port = 22\n    to_port = 22\n    protocol = "tcp"\n    cidr_blocks = var.cidrs\n'
        findings, notes = self.ingress(body)
        self.assertEqual(findings, [])
        self.assertEqual([n["check"] for n in notes], ["open-ingress"])

    def test_world_source_with_variable_ports_is_not_evaluated(self):
        body = '    from_port = var.port\n    to_port = var.port\n    protocol = "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n'
        findings, notes = self.ingress(body)
        self.assertEqual(findings, [])
        self.assertIn("ports are not literal values", notes[0]["detail"])

    def test_standalone_rule_resources(self):
        files = {"main.tf": 'resource "aws_security_group_rule" "in" {\n  type = "ingress"\n  from_port = 3389\n'
                            '  to_port = 3389\n  protocol = "tcp"\n  cidr_blocks = ["0.0.0.0/0"]\n}\n'
                            'resource "aws_security_group_rule" "out" {\n  type = "egress"\n  from_port = 0\n'
                            '  to_port = 0\n  protocol = "-1"\n  cidr_blocks = ["0.0.0.0/0"]\n}\n'
                            'resource "aws_vpc_security_group_ingress_rule" "db" {\n  cidr_ipv4 = "0.0.0.0/0"\n'
                            '  from_port = 3306\n  to_port = 3306\n  ip_protocol = "tcp"\n}\n'
                            'resource "aws_vpc_security_group_ingress_rule" "all" {\n  cidr_ipv6 = "::/0"\n'
                            '  ip_protocol = "-1"\n}\n'}
        self.assertEqual(self.checks(files), ["open-ingress aws_security_group_rule.in",
                                              "open-ingress aws_vpc_security_group_ingress_rule.all",
                                              "open-ingress aws_vpc_security_group_ingress_rule.db"])

    def test_cloudformation_ingress_resource(self):
        files = {"t.json": cfn({"Rule": {"Type": "AWS::EC2::SecurityGroupIngress", "Properties": {
            "IpProtocol": "tcp", "FromPort": "22", "ToPort": "22", "CidrIp": "0.0.0.0/0"}}})}
        self.assertEqual(self.checks(files), ["open-ingress Resources.Rule"])

    def test_azure_rules(self):
        rule = ('resource "azurerm_network_security_rule" "%s" {\n  direction = "%s"\n  access = "%s"\n'
                '  protocol = "Tcp"\n  source_address_prefix = "*"\n  %s\n}\n')
        files = {"main.tf": rule % ("out", "Outbound", "Allow", 'destination_port_range = "22"')
                 + rule % ("deny", "Inbound", "Deny", 'destination_port_range = "22"')
                 + rule % ("list", "Inbound", "Allow", 'destination_port_ranges = ["443", "1433-1434"]')
                 + rule % ("any", "Inbound", "Allow", 'destination_port_range = "*"')}
        result = self.scan_tree(files)
        self.assertEqual(sorted((f["resource"], f["message"]) for f in result["findings"]), [
            ("azurerm_network_security_rule.any", "Inbound traffic from * is allowed on every port."),
            ("azurerm_network_security_rule.list", "Inbound traffic from * is allowed on port 1433 (SQL Server).")])

    def test_gcp_egress_disabled_and_tagged_rules_are_not_findings(self):
        rule = ('resource "google_compute_firewall" "%s" {\n  %s\n  allow {\n    protocol = "tcp"\n'
                '    ports = ["22"]\n  }\n}\n')
        files = {"main.tf": rule % ("egress", 'direction = "EGRESS"\n  source_ranges = ["0.0.0.0/0"]')
                 + rule % ("off", 'disabled = true\n  source_ranges = ["0.0.0.0/0"]')
                 + rule % ("tagged", 'source_tags = ["bastion"]')}
        self.assertEqual(self.checks(files), [])


class OtherCheckTests(TempTree, unittest.TestCase):
    def test_single_instance_respects_count(self):
        instance = 'resource "aws_instance" "web" {\n%s}\n'
        self.assertEqual(self.checks({"main.tf": instance % ""}), ["single-instance aws_instance.web"])
        self.assertEqual(self.checks({"main.tf": instance % "  count = 1\n"}), ["single-instance aws_instance.web"])
        self.assertEqual(self.checks({"main.tf": instance % "  count = 3\n"}), [])
        self.assertEqual(self.checks({"main.tf": instance % "  count = 0\n"}), [])
        files = {"main.tf": instance % "  count = var.web_count\n"}
        self.assertEqual(self.checks(files), [])
        self.assertEqual(self.skipped(files), ["single-instance aws_instance.web"])

    def test_public_access_block_lists_the_flags_that_are_off(self):
        files = {"main.tf": 'resource "aws_s3_bucket_public_access_block" "b" {\n  block_public_acls = true\n'
                            '  block_public_policy = var.block\n  ignore_public_acls = false\n}\n'}
        result = self.scan_tree(files)
        self.assertEqual(len(result["findings"]), 1)
        self.assertIn("Not switched on: ignore_public_acls, restrict_public_buckets.", result["findings"][0]["message"])
        self.assertEqual([n["detail"] for n in result["not_evaluated"]], ["block_public_policy = var.block"])

    def test_cloudformation_bucket_without_public_access_block_is_not_flagged(self):
        self.assertEqual(self.checks({"t.json": cfn({"B": {"Type": "AWS::S3::Bucket", "Properties": {}}})}), [])

    def test_flexible_server_high_availability(self):
        server = 'resource "azurerm_mysql_flexible_server" "db" {\n%s}\n'
        result = self.scan_tree({"main.tf": server % '  high_availability {\n    mode = "SameZone"\n  }\n'})
        self.assertEqual([(f["check"], f["severity"]) for f in result["findings"]], [("db-single-zone", "low")])
        self.assertEqual(self.checks({"main.tf": server % '  high_availability {\n    mode = "ZoneRedundant"\n  }\n'}), [])
        self.assertEqual(self.checks({"main.tf": server % ""}), ["db-single-zone azurerm_mysql_flexible_server.db"])

    def test_gcp_bucket_binding_with_all_users(self):
        files = {"main.tf": 'resource "google_storage_bucket_iam_binding" "b" {\n'
                            '  members = ["user:a@example.com", "allAuthenticatedUsers"]\n}\n'}
        self.assertEqual(self.checks(files), ["public-storage google_storage_bucket_iam_binding.b"])

    def test_kubernetes_replicas(self):
        def deployment(spec):
            return {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "web"}, "spec": spec}
        hpa = {"apiVersion": "autoscaling/v2", "kind": "HorizontalPodAutoscaler", "metadata": {"name": "web"},
               "spec": {"scaleTargetRef": {"kind": "Deployment", "name": "web"}}}
        self.assertEqual(self.checks({"d.json": deployment({})}), ["single-instance Deployment/web"])
        self.assertEqual(self.checks({"d.json": deployment({"replicas": 1})}), ["single-instance Deployment/web"])
        self.assertEqual(self.checks({"d.json": deployment({"replicas": 2})}), [])
        self.assertEqual(self.checks({"d.json": deployment({}), "hpa.json": hpa}), [])

    def test_module_is_reported_as_not_evaluated(self):
        result = self.scan_tree({"main.tf": 'module "vpc" {\n  source = "./modules/vpc"\n}\n'})
        self.assertEqual(result["resources"], [])
        self.assertEqual([(n["check"], n["resource"]) for n in result["not_evaluated"]], [("module", "module.vpc")])
        self.assertIn('source = "./modules/vpc"', result["not_evaluated"][0]["detail"])


class PlaintextSecretTests(TempTree, unittest.TestCase):
    def test_names_that_are_not_secrets_and_values_that_are_references(self):
        files = {"main.tf": 'resource "aws_db_instance" "db" {\n  multi_az = true\n  storage_encrypted = true\n'
                            '  deletion_protection = true\n  backup_retention_period = 7\n'
                            '  password = var.db_password\n  manage_master_user_password = true\n'
                            '  master_user_secret_kms_key_id = "alias/db"\n  key_name = "deployer"\n'
                            '  password_length = 32\n  secret_name = "prod/db"\n  token_ttl = "1h"\n'
                            '  secret = "db-credentials"\n  username = "admin"\n  auth_token = ""\n}\n'}
        self.assertEqual(self.checks(files), [])

    def test_terraform_places_a_secret_can_be_written(self):
        files = {
            "main.tf": 'provider "aws" {\n  secret_key = "placeholder-1"\n}\n'
                       'variable "api_token" {\n  default = "placeholder-2"\n}\n'
                       'variable "region" {\n  default = "eu-west-1"\n}\n'
                       'locals {\n  db_password = "placeholder-3"\n}\n'
                       'module "app" {\n  source = "./app"\n  client_secret = "placeholder-4"\n}\n'
                       'resource "azurerm_container_app" "app" {\n  template {\n    container {\n      env {\n'
                       '        name = "API_KEY"\n        value = "placeholder-5"\n      }\n    }\n  }\n}\n'
                       'resource "aws_ssm_parameter" "p" {\n  type = "SecureString"\n  value = "placeholder-6"\n}\n'
                       'resource "aws_ssm_parameter" "plain" {\n  type = "String"\n  value = "eu-west-1"\n}\n'
                       'resource "aws_secretsmanager_secret_version" "v" {\n  secret_string = "placeholder-7"\n}\n',
            "prod.tfvars": 'db_password = "placeholder-8"\nregion = "eu-west-1"\n',
        }
        self.assertEqual(self.checks(files), [
            "plaintext-secret aws_secretsmanager_secret_version.v", "plaintext-secret aws_ssm_parameter.p",
            "plaintext-secret azurerm_container_app.app", "plaintext-secret locals",
            "plaintext-secret module.app", "plaintext-secret provider.aws", "plaintext-secret tfvars",
            "plaintext-secret var.api_token"])

    def test_cloudformation_dynamic_reference_and_service_token_are_not_flagged(self):
        files = {"t.json": cfn({
            "Db": {"Type": "AWS::RDS::DBCluster", "Properties": {
                "StorageEncrypted": True, "DeletionProtection": True,
                "MasterUserPassword": "{{resolve:secretsmanager:db:SecretString:password}}"}},
            "Custom": {"Type": "Custom::Thing", "Properties": {"ServiceToken": "arn:aws:lambda:eu-west-1:1:function:f"}},
        }, {"DbPassword": {"Type": "String", "NoEcho": True}})}
        self.assertEqual(self.checks(files), [])

    def test_cloudformation_container_environment_and_secret_string(self):
        files = {"t.json": cfn({
            "Task": {"Type": "AWS::ECS::TaskDefinition", "Properties": {"ContainerDefinitions": [{
                "Name": "api", "Environment": [{"Name": "DB_PASSWORD", "Value": "placeholder"}],
                "Secrets": [{"Name": "API_TOKEN", "ValueFrom": "arn:aws:ssm:eu-west-1:1:parameter/token"}]}]}},
            "Secret": {"Type": "AWS::SecretsManager::Secret", "Properties": {"SecretString": "placeholder"}},
        })}
        self.assertEqual(self.checks(files), ["plaintext-secret Resources.Secret", "plaintext-secret Resources.Task"])

    def test_kubernetes_secret_manifests(self):
        def secret(extra):
            return dict({"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "s"}}, **extra)
        self.assertEqual(self.checks({"s.json": secret({"stringData": {"password": "placeholder"}})}),
                         ["plaintext-secret Secret/s"])
        self.assertEqual(self.checks({"s.json": secret({"data": {"password": "ENC[x]"}, "sops": {"version": "3"}})}), [])
        self.assertEqual(self.checks({"s.json": secret({})}), [])

    def test_compose_variable_references_are_not_flagged(self):
        files = {"docker-compose.json": {"services": {"db": {"image": "postgres:16", "environment": {
            "POSTGRES_PASSWORD": "${DB_PASSWORD}", "POSTGRES_PASSWORD_FILE": "/run/secrets/db"}}}}}
        self.assertEqual(self.checks(files), [])

    def test_looks_secret(self):
        for name in ("password", "MasterUserPassword", "DB_PASSWORD", "client_secret", "API-KEY", "auth_token",
                     "secret_access_key", "tls_private_key"):
            self.assertTrue(iac_checks.looks_secret(name), name)
        for name in ("secret", "token", "ServiceToken", "password_length", "secret_arn", "AWS_ACCESS_KEY_ID",
                     "key_name", "kms_key_id", "username", "public_key"):
            self.assertFalse(iac_checks.looks_secret(name), name)


class ListingTests(unittest.TestCase):
    def test_every_check_is_listed_with_the_types_it_reads(self):
        listed = dict((entry["check"], entry) for entry in iac_checks.list_checks())
        self.assertEqual(set(listed), set(iac_checks.CHECKS))
        for check, entry in listed.items():
            self.assertTrue(entry["resource_types"], check)
            self.assertIn(entry["severity"], iac_checks.SEVERITIES)

    def test_every_checked_type_is_in_the_inventory_catalogue(self):
        for entry in iac_checks.list_checks():
            for rtype in entry["resource_types"]:
                self.assertIn(rtype, iac_inventory.TYPE_INDEX, "%s reads an uncatalogued type" % entry["check"])

    def test_command_line(self):
        code, out, _ = run(iac_checks, [])
        self.assertEqual(code, 0)
        self.assertIn("open-ingress  [high, security]", out)
        code, out, _ = run(iac_checks, ["--json"])
        self.assertEqual(code, 0)
        self.assertEqual(len(json.loads(out)), len(iac_checks.CHECKS))
        self.assertEqual(run(iac_checks, ["--nope"])[0], 2)


if __name__ == "__main__":
    unittest.main()
