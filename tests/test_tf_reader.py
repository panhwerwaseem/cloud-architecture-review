import json
import unittest

from support import TempTree, run

import tf_reader  # noqa: E402  (support puts the scripts directory on sys.path)
from tf_reader import ReadError, Unknown, evaluate, read_text


def resource(text):
    return read_text(text).blocks[0]


class EvaluateTests(unittest.TestCase):
    def test_literals(self):
        self.assertIs(evaluate("true"), True)
        self.assertIs(evaluate("false"), False)
        self.assertIsNone(evaluate("null"))
        self.assertEqual(evaluate("42"), 42)
        self.assertEqual(evaluate("-1"), -1)
        self.assertEqual(evaluate("1.5"), 1.5)
        self.assertEqual(evaluate('"eu-west-1"'), "eu-west-1")

    def test_string_escapes(self):
        self.assertEqual(evaluate(r'"a\"b}c"'), 'a"b}c')
        self.assertEqual(evaluate('"$${literal}"'), "${literal}")

    def test_expressions_are_not_evaluated(self):
        for raw in ("var.multi_az", "local.name", "module.vpc.id", "aws_kms_key.main.arn",
                    'lookup(var.m, "k", false)', "var.prod ? true : false", '"db-${var.env}"',
                    "[for s in var.subnets : s.id]", "{for k, v in var.m : k => v}",
                    "[1, 2][0]", '"a" == "b"', "!var.disabled", "1 + 1"):
            value = evaluate(raw)
            self.assertIsInstance(value, Unknown, raw)
            self.assertEqual(value.raw, raw)

    def test_list_keeps_literals_and_marks_the_rest(self):
        value = evaluate('["0.0.0.0/0", var.office_cidr, 22,]')
        self.assertEqual(value[0], "0.0.0.0/0")
        self.assertIsInstance(value[1], Unknown)
        self.assertEqual(value[2], 22)
        self.assertEqual(len(value), 3)

    def test_map_with_equals_colon_commas_and_newlines(self):
        value = evaluate('{ Name = "a", "Env" : "b"\n  count = 3\n  ref = var.x }')
        self.assertEqual(value["Name"], "a")
        self.assertEqual(value["Env"], "b")
        self.assertEqual(value["count"], 3)
        self.assertIsInstance(value["ref"], Unknown)

    def test_map_with_computed_key_is_not_evaluated(self):
        self.assertIsInstance(evaluate('{ (var.key) = "a" }'), Unknown)

    def test_nested_collections(self):
        self.assertEqual(evaluate('[{ a = 1 }, ["x", "y"]]'), [{"a": 1}, ["x", "y"]])

    def test_heredoc_is_not_evaluated_and_its_text_is_not_kept(self):
        value = evaluate("<<-EOT\n    top secret line\n    EOT")
        self.assertIsInstance(value, Unknown)
        self.assertNotIn("top secret", value.raw)
        wrapped = evaluate("base64encode(<<EOT\nexport KEY=top secret\nEOT\n)")
        self.assertIsInstance(wrapped, Unknown)
        self.assertNotIn("top secret", wrapped.raw)
        self.assertIn("base64encode(<<EOT (heredoc text not shown)", wrapped.raw)


class ReadTextTests(unittest.TestCase):
    def test_resource_labels_attributes_and_lines(self):
        block = resource('\n\nresource "aws_db_instance" "main" {\n  multi_az = true\n  name = var.name\n}\n')
        self.assertEqual((block.type, block.labels, block.line), ("resource", ["aws_db_instance", "main"], 3))
        self.assertIs(block.attrs["multi_az"].value, True)
        self.assertEqual(block.attrs["multi_az"].line, 4)
        self.assertIsInstance(block.attrs["name"].value, Unknown)
        self.assertEqual(block.attrs["name"].line, 5)

    def test_comments_with_braces_and_quotes_are_ignored(self):
        block = resource('resource "a" "b" {\n  # a { brace and a " quote\n  x = 1 // } trailing\n'
                         '  /* block {\n comment */\n  y = 2 # don\'t\n}\n')
        self.assertEqual(block.attrs["x"].value, 1)
        self.assertEqual(block.attrs["y"].value, 2)

    def test_braces_inside_strings_do_not_close_blocks(self):
        block = resource('resource "a" "b" {\n  x = "}{"\n  y = "${var.m["k}"]}"\n  z = 3\n}\n')
        self.assertEqual(block.attrs["x"].value, "}{")
        self.assertIsInstance(block.attrs["y"].value, Unknown)
        self.assertEqual(block.attrs["z"].value, 3)

    def test_heredoc_with_unbalanced_braces(self):
        block = resource('resource "a" "b" {\n  policy = <<EOT\n{ "Statement": [ }\nEOT\n  after = true\n}\n')
        self.assertIsInstance(block.attrs["policy"].value, Unknown)
        self.assertIs(block.attrs["after"].value, True)

    def test_multi_line_function_call_is_one_unevaluated_expression(self):
        block = resource('resource "a" "b" {\n  policy = jsonencode({\n    Action = "*"\n  })\n  after = 1\n}\n')
        self.assertIsInstance(block.attrs["policy"].value, Unknown)
        self.assertEqual(block.attrs["after"].value, 1)

    def test_multi_line_list_with_comments(self):
        block = resource('resource "a" "b" {\n  cidrs = [\n    "10.0.0.0/8", # internal\n    "0.0.0.0/0",\n  ]\n}\n')
        self.assertEqual(block.attrs["cidrs"].value, ["10.0.0.0/8", "0.0.0.0/0"])

    def test_nested_and_repeated_blocks(self):
        block = resource('resource "a" "b" {\n  settings {\n    backup { enabled = true }\n  }\n'
                         '  ingress {\n    from_port = 22\n  }\n  ingress {\n    from_port = 443\n  }\n}\n')
        settings = [b for b in block.blocks if b.type == "settings"][0]
        self.assertIs(settings.blocks[0].attrs["enabled"].value, True)
        ports = [b.attrs["from_port"].value for b in block.blocks if b.type == "ingress"]
        self.assertEqual(ports, [22, 443])

    def test_dynamic_block_is_kept_as_a_dynamic_block(self):
        block = resource('resource "a" "b" {\n  dynamic "ingress" {\n    for_each = var.rules\n'
                         '    content {\n      from_port = ingress.value\n    }\n  }\n}\n')
        dynamic = block.blocks[0]
        self.assertEqual((dynamic.type, dynamic.labels), ("dynamic", ["ingress"]))
        self.assertIsInstance(dynamic.attrs["for_each"].value, Unknown)

    def test_tfvars_attributes_are_read_at_the_top_level(self):
        root = read_text('region = "eu-west-1"\ncount = 2\n')
        self.assertEqual(root.attrs["region"].value, "eu-west-1")
        self.assertEqual(root.attrs["count"].line, 2)

    def test_unclosed_block_reports_the_opening_line(self):
        with self.assertRaises(ReadError) as caught:
            read_text('\nresource "a" "b" {\n  x = 1\n')
        self.assertEqual(caught.exception.line, 2)

    def test_other_broken_input_raises_read_error(self):
        for text in ('x = "unclosed\n', "x = [1, 2\n", "}\n", 'resource "a" "b" {\n  x = <<EOT\nnever closed\n}\n',
                     "resource\n", "x = 1 /* never closed"):
            with self.assertRaises(ReadError, msg=text):
                read_text(text)


class CommandLineTests(TempTree, unittest.TestCase):
    def setUp(self):
        self.root = self.tree({
            "main.tf": 'resource "aws_db_instance" "main" {\n  multi_az = true\n'
                       '  password = "hunter2-placeholder"\n  name = var.name\n}\n',
            "broken.tf": 'resource "a" "b" {\n',
        })

    def test_string_values_are_hidden_by_default(self):
        code, out, _ = run(tf_reader, [str(self.root / "main.tf")])
        self.assertEqual(code, 0)
        self.assertNotIn("hunter2", out)
        self.assertIn("multi_az = true", out)
        self.assertIn("name = NOT EVALUATED: var.name", out)

    def test_values_flag_shows_strings(self):
        code, out, _ = run(tf_reader, [str(self.root / "main.tf"), "--values"])
        self.assertEqual(code, 0)
        self.assertIn("hunter2-placeholder", out)

    def test_json_output(self):
        code, out, _ = run(tf_reader, [str(self.root / "main.tf"), "--json"])
        block = json.loads(out)[0]["blocks"][0]
        self.assertEqual(code, 0)
        self.assertEqual(block["labels"], ["aws_db_instance", "main"])
        self.assertEqual(block["attributes"]["name"]["value"], {"not_evaluated": "var.name"})
        self.assertEqual(block["attributes"]["multi_az"], {"line": 2, "value": True})

    def test_unreadable_file_gives_exit_code_1(self):
        code, out, _ = run(tf_reader, [str(self.root / "broken.tf"), str(self.root / "main.tf")])
        self.assertEqual(code, 1)
        self.assertIn("NOT READ: line 1", out)
        self.assertIn("aws_db_instance", out)

    def test_missing_file_and_missing_argument_give_exit_code_2(self):
        code, _, err = run(tf_reader, [str(self.root / "nope.tf")])
        self.assertEqual(code, 2)
        self.assertIn("cannot open", err)
        self.assertEqual(run(tf_reader, [])[0], 2)


if __name__ == "__main__":
    unittest.main()
