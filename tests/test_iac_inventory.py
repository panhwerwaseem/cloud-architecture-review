import io
import json
import subprocess
import sys
import types
import unittest
from contextlib import redirect_stdout

from support import FIXTURES, ROOT, SKILL, TempTree, run, scan

import iac_checks  # noqa: E402  (support puts the scripts directory on sys.path)
import iac_inventory  # noqa: E402

# The planted weaknesses, as "check resource". The scan must report exactly these.
PLANTED = {
    "shop-aws": [
        "db-backups-disabled aws_db_instance.orders",
        "db-no-point-in-time-recovery aws_dynamodb_table.carts",
        "db-single-zone aws_db_instance.orders",
        "log-retention-unbounded aws_cloudwatch_log_group.notify",
        "no-deletion-protection aws_db_instance.orders",
        "no-deletion-protection aws_dynamodb_table.carts",
        "open-ingress aws_security_group.db",
        "open-ingress aws_security_group.web",
        "open-ingress aws_security_group_rule.metrics",
        "plaintext-secret aws_db_instance.orders",
        "plaintext-secret aws_lambda_function.notify",
        "plaintext-secret tfvars",
        "public-access-block-disabled aws_s3_bucket_public_access_block.receipts",
        "public-database aws_db_instance.orders",
        "public-storage aws_s3_bucket.receipts",
        "single-instance aws_instance.web",
        "storage-not-encrypted aws_db_instance.orders",
        "storage-not-encrypted aws_ebs_volume.exports",
    ],
    "ledger-azure": [
        "db-open-to-azure-services azurerm_postgresql_flexible_server_firewall_rule.azure_services",
        "db-single-zone azurerm_postgresql_flexible_server.ledger",
        "insecure-transport azurerm_storage_account.statements",
        "insecure-transport azurerm_storage_account.statements",
        "no-deletion-protection azurerm_key_vault.ledger",
        "open-ingress azurerm_network_security_group.app",
        "open-ingress azurerm_network_security_rule.ssh",
        "plaintext-secret azurerm_key_vault_secret.signing",
        "plaintext-secret azurerm_linux_virtual_machine.app",
        "plaintext-secret azurerm_postgresql_flexible_server.ledger",
        "public-database azurerm_postgresql_flexible_server_firewall_rule.anywhere",
        "public-storage azurerm_storage_container.statements",
        "single-instance azurerm_linux_virtual_machine.app",
        "single-instance azurerm_linux_virtual_machine_scale_set.workers",
        "storage-not-zone-redundant azurerm_storage_account.statements",
    ],
    "tracker-gcp": [
        "db-backups-disabled google_sql_database_instance.tracker",
        "db-single-zone google_redis_instance.cache",
        "db-single-zone google_sql_database_instance.tracker",
        "no-deletion-protection google_sql_database_instance.tracker",
        "open-ingress google_compute_firewall.debug",
        "open-ingress google_compute_firewall.ssh",
        "plaintext-secret Deployment/tracker-api",
        "plaintext-secret Secret/tracker-secrets",
        "plaintext-secret google_sql_database_instance.tracker",
        "public-database google_sql_database_instance.tracker",
        "public-storage google_storage_bucket_iam_member.public_read",
        "single-instance Deployment/tracker-api",
        "single-instance google_compute_instance.mailer",
    ],
    "billing-cloudformation": [
        "db-backups-disabled Resources.Database",
        "db-no-point-in-time-recovery Resources.InvoiceTable",
        "log-retention-unbounded Resources.ExportLogs",
        "no-deletion-protection Resources.Database",
        "no-deletion-protection Resources.InvoiceTable",
        "open-ingress Resources.DbSecurityGroup",
        "plaintext-secret Parameters",
        "plaintext-secret Resources.ExportFunction",
        "plaintext-secret services.api",
        "plaintext-secret services.db",
        "public-access-block-disabled Resources.InvoiceBucket",
        "public-database Resources.Database",
        "public-storage Resources.InvoiceBucket",
        "single-instance Resources.Worker",
        "storage-not-encrypted Resources.Database",
    ],
    "well-configured": [],
}
NOT_EVALUATED = {
    "shop-aws": [
        "db-backups-disabled aws_db_instance.reporting",
        "db-single-zone aws_db_instance.reporting",
        "module module.vpc",
        "open-ingress aws_security_group.internal",
    ],
    "ledger-azure": ["storage-not-zone-redundant azurerm_storage_account.archive"],
    "tracker-gcp": [],
    "billing-cloudformation": ["db-single-zone Resources.Database"],
    "well-configured": [],
}


class FixtureTests(unittest.TestCase):
    def test_fixture_list_is_complete(self):
        self.assertEqual(sorted(p.name for p in FIXTURES.iterdir() if p.is_dir()), sorted(PLANTED))

    def test_each_fixture_reports_exactly_its_planted_weaknesses(self):
        for name, planted in PLANTED.items():
            code, result = scan(FIXTURES / name)
            found = sorted("%s %s" % (f["check"], f["resource"]) for f in result["findings"])
            self.assertEqual(found, planted, name)
            skipped = sorted("%s %s" % (n["check"], n["resource"]) for n in result["not_evaluated"])
            self.assertEqual(skipped, NOT_EVALUATED[name], name)
            self.assertEqual(code, 1 if planted else 0, name)

    def test_every_finding_names_a_file_a_resource_and_a_line_or_path(self):
        for name in PLANTED:
            for finding in scan(FIXTURES / name)[1]["findings"]:
                self.assertTrue((FIXTURES / name / finding["file"]).is_file(), finding)
                self.assertTrue(finding["resource"] and finding["path"] and finding["message"], finding)
                if finding["file"].endswith((".tf", ".tfvars")):
                    self.assertGreater(finding["line"], 0, finding)

    def test_terraform_finding_lines_point_at_the_attribute(self):
        findings = scan(FIXTURES / "shop-aws")[1]["findings"]
        public = [f for f in findings if f["check"] == "public-database"][0]
        lines = (FIXTURES / "shop-aws" / public["file"]).read_text().splitlines()
        self.assertIn("publicly_accessible", lines[public["line"] - 1])

    def test_secret_values_are_never_printed(self):
        for name in PLANTED:
            for flags in ([], ["--json"]):
                _, out, err = run(iac_inventory, [str(FIXTURES / name)] + flags)
                self.assertNotIn("example-only", out + err, name)
                self.assertNotIn("ZXhhbXBsZS1vbmx5", out + err, name)

    def test_output_is_deterministic(self):
        first = run(iac_inventory, [str(FIXTURES / "shop-aws")])
        self.assertEqual(first, run(iac_inventory, [str(FIXTURES / "shop-aws")]))

    def test_inventory_by_cloud_and_category(self):
        inventory = scan(FIXTURES / "tracker-gcp")[1]["inventory"]
        self.assertEqual(inventory["gcp"]["network"], {"google_compute_firewall": 3, "google_compute_network": 1})
        self.assertEqual(inventory["kubernetes"]["compute"], {"Deployment": 1})
        self.assertEqual(scan(FIXTURES / "billing-cloudformation")[1]["inventory"]["compose"],
                         {"compute": {"service": 2}})

    def test_missing_categories_are_reported_as_not_found_in_code(self):
        result = scan(FIXTURES / "tracker-gcp")[1]
        self.assertEqual(result["not_found_in_code"], [{"cloud": "gcp", "categories": ["observability"]}])
        self.assertEqual(scan(FIXTURES / "well-configured")[1]["not_found_in_code"], [])

    def test_fail_on_levels(self):
        self.assertEqual(scan(FIXTURES / "shop-aws", "--fail-on", "never")[0], 0)
        self.assertEqual(scan(FIXTURES / "well-configured", "--fail-on", "low")[0], 0)
        code, result = scan(FIXTURES / "shop-aws", "--fail-on", "low")
        self.assertEqual((code, result["summary"]["blocking"]), (1, len(PLANTED["shop-aws"])))

    def test_text_report_sections(self):
        code, out, _ = run(iac_inventory, [str(FIXTURES / "shop-aws")])
        self.assertEqual(code, 1)
        for expected in ("INVENTORY (14 resources)", "FINDINGS (9 high, 7 medium, 2 low)", "NOT EVALUATED (4)",
                         "[high] open-ingress  aws_security_group.db  (network.tf:33)",
                         "multi_az = var.reporting_multi_az", "RESULT: 9 finding(s) at or above 'high'."):
            self.assertIn(expected, out)


class WalkAndInputTests(TempTree, unittest.TestCase):
    DB = 'resource "aws_db_instance" "db" {\n  publicly_accessible = true\n}\n'

    def test_unknown_types_are_counted_but_not_categorised(self):
        result = self.scan_tree({"main.tf": 'resource "aws_sqs_queue" "q" {\n}\nresource "random_id" "r" {\n}\n'})
        self.assertEqual(result["inventory"], {"aws": {"uncategorised": {"aws_sqs_queue": 1}},
                                               "other": {"uncategorised": {"random_id": 1}}})

    def test_hidden_directories_node_modules_and_excludes_are_skipped(self):
        files = {"main.tf": self.DB, ".terraform/modules/x/main.tf": self.DB, "node_modules/p/main.tf": self.DB,
                 "legacy/main.tf": self.DB}
        self.assertEqual(len(self.scan_tree(files)["resources"]), 2)
        self.assertEqual(len(self.scan_tree(files, "--exclude", "legacy")["resources"]), 1)

    def test_unreadable_terraform_file_is_listed_and_the_rest_is_scanned(self):
        result = self.scan_tree({"main.tf": self.DB, "broken.tf": 'resource "a" "b" {\n'})
        self.assertEqual(len(result["resources"]), 1)
        self.assertEqual([entry["file"] for entry in result["files_not_read"]], ["broken.tf"])
        self.assertIn("line 1", result["files_not_read"][0]["reason"])

    def test_json_that_is_not_infrastructure_code_is_ignored(self):
        result = self.scan_tree({"main.tf": self.DB, "package.json": {"name": "app", "services": ["a"]},
                                 "tsconfig.json": "{ // comment\n}", "infra.tf.json": {"resource": {}}})
        self.assertEqual(result["files_without_infrastructure_code"], 1)
        self.assertEqual(sorted(entry["file"] for entry in result["files_not_read"]),
                         ["infra.tf.json", "tsconfig.json"])

    def test_deeply_nested_file_is_listed_as_not_read(self):
        result = self.scan_tree({"main.tf": self.DB, "deep.json": "[" * 100000 + "]" * 100000})
        self.assertEqual(result["files_not_read"], [{"file": "deep.json", "reason": "nested too deeply to read"}])

    def test_several_json_documents_in_one_file(self):
        doc = '{"apiVersion": "v1", "kind": "Service", "metadata": {"name": "%s"}}\n'
        result = self.scan_tree({"all.json": doc % "a" + doc % "b"})
        self.assertEqual([r["address"] for r in result["resources"]], ["Service/a", "Service/b"])

    def test_kubernetes_list_document(self):
        items = [{"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "sa"}}]
        result = self.scan_tree({"list.json": {"apiVersion": "v1", "kind": "List", "items": items}})
        self.assertEqual(result["inventory"], {"kubernetes": {"identity": {"ServiceAccount": 1}}})

    def test_single_file_path(self):
        root = self.tree({"main.tf": self.DB, "other.tf": self.DB})
        self.assertEqual(len(scan(root / "main.tf")[1]["resources"]), 1)

    def test_input_errors_give_exit_code_2(self):
        root = self.tree({"README.md": "nothing here", "data.json": {"a": 1}, "broken.tf": "}"})
        code, out, err = run(iac_inventory, [str(root)])
        self.assertEqual((code, out), (2, ""))
        self.assertIn("no infrastructure code could be read", err)
        self.assertIn("broken.tf", err)
        self.assertEqual(run(iac_inventory, [str(root / "missing")])[0], 2)
        self.assertEqual(run(iac_inventory, [str(root / "README.md")])[0], 2)
        self.assertEqual(run(iac_inventory, [])[0], 2)
        self.assertEqual(run(iac_inventory, [str(root), "--fail-on", "sometimes"])[0], 2)

    def test_list_types_matches_the_catalogue(self):
        code, out, _ = run(iac_inventory, ["--list-types", "--json"])
        listed = json.loads(out)
        self.assertEqual(code, 0)
        self.assertIn("aws_db_instance", listed["aws"]["data"])
        self.assertIn("AWS::RDS::DBInstance", listed["aws"]["data"])
        self.assertEqual(sum(len(names) for groups in listed.values() for names in groups.values()),
                         len(iac_inventory.TYPE_INDEX))
        self.assertEqual(len(run(iac_inventory, ["--list-types"])[1].splitlines()), len(iac_inventory.TYPE_INDEX))


class YamlPolicyTests(TempTree, unittest.TestCase):
    """YAML is read only through PyYAML. These tests never need it installed."""
    MANIFEST = {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "web"}, "spec": {"replicas": 1}}

    def setUp(self):
        self.saved = sys.modules.get("yaml", self)
        self.addCleanup(self.restore)
        self.root = self.tree({"main.tf": 'resource "aws_instance" "web" {\n  count = 2\n}\n',
                               "k8s/web.yaml": self.MANIFEST})  # JSON text is also valid YAML

    def restore(self):
        if self.saved is self:
            sys.modules.pop("yaml", None)
        else:
            sys.modules["yaml"] = self.saved

    def without_pyyaml(self):
        sys.modules["yaml"] = None  # makes "import yaml" raise ImportError

    def with_fake_pyyaml(self, fail=False):
        fake = types.ModuleType("yaml")
        fake.YAMLError = type("YAMLError", (Exception,), {})

        def safe_load_all(text):
            if fail:
                raise fake.YAMLError("could not determine a constructor for the tag '!Ref'")
            return iter([json.loads(text)])
        fake.safe_load_all = safe_load_all
        sys.modules["yaml"] = fake

    def test_yaml_without_pyyaml_is_an_input_error_that_lists_the_options(self):
        self.without_pyyaml()
        code, out, err = run(iac_inventory, [str(self.root)])
        self.assertEqual((code, out), (2, ""))
        for expected in ("k8s/web.yaml", "pip install pyyaml", "yq -o=json", "cfn-flip", "--skip-yaml"):
            self.assertIn(expected, err)

    def test_skip_yaml_scans_the_rest_and_lists_the_yaml_as_not_read(self):
        self.without_pyyaml()
        code, result = scan(self.root, "--skip-yaml")
        self.assertEqual(code, 0)
        self.assertEqual([r["address"] for r in result["resources"]], ["aws_instance.web"])
        self.assertEqual(result["files_not_read"], [{"file": "k8s/web.yaml", "reason": "YAML, skipped by --skip-yaml"}])

    def test_no_yaml_files_means_pyyaml_is_never_needed(self):
        self.without_pyyaml()
        self.assertEqual(scan(self.tree({"main.tf": 'resource "aws_vpc" "v" {\n}\n'}))[0], 0)

    def test_yaml_is_read_when_pyyaml_is_importable(self):
        self.with_fake_pyyaml()
        result = scan(self.root)[1]
        self.assertEqual(result["files_read"], {"kubernetes": 1, "terraform": 1})
        self.assertEqual([f["resource"] for f in result["findings"]], ["Deployment/web"])

    def test_yaml_that_pyyaml_rejects_is_listed_as_not_read(self):
        self.with_fake_pyyaml(fail=True)
        result = scan(self.root)[1]
        self.assertEqual([entry["file"] for entry in result["files_not_read"]], ["k8s/web.yaml"])
        self.assertIn("cfn-flip", result["files_not_read"][0]["reason"])


class DocumentationTests(unittest.TestCase):
    def test_reference_lists_every_known_type_and_check(self):
        text = (SKILL / "references" / "known-types-and-checks.md").read_text(encoding="utf-8")
        for rtype in iac_inventory.TYPE_INDEX:
            self.assertIn("`%s`" % rtype, text)
        for check in iac_checks.CHECKS:
            self.assertIn("`%s`" % check, text)

    def test_every_script_has_help_with_examples(self):
        for script in ("iac_inventory.py", "iac_checks.py", "tf_reader.py"):
            done = subprocess.run([sys.executable, str(SKILL / "scripts" / script), "--help"],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(done.returncode, 0, script)
            self.assertIn(b"Examples:", done.stdout, script)
            self.assertIn(b"Exit codes:", done.stdout, script)


class ValidateRepoTests(unittest.TestCase):
    def test_repository_passes_its_own_validator(self):
        sys.path.insert(0, str(ROOT / "tools"))
        import validate
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = validate.main(["validate.py", str(ROOT)])
        self.assertEqual(code, 0, buffer.getvalue())


if __name__ == "__main__":
    unittest.main()
