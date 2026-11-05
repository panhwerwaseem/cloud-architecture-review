"""Shared helpers for the test modules."""
import io
import json
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILL = ROOT / "skills" / "cloud-architecture-review"
FIXTURES = SKILL / "evals" / "files"
sys.path.insert(0, str(SKILL / "scripts"))

import iac_inventory  # noqa: E402


def run(module, argv):
    """Call module.main(argv). Return (exit code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            code = module.main(argv)
        except SystemExit as exc:  # argparse usage errors
            code = exc.code
    return code, out.getvalue(), err.getvalue()


def scan(path, *flags):
    """Run iac_inventory on a path with --json. Return (exit code, result)."""
    code, out, err = run(iac_inventory, [str(path), "--json"] + list(flags))
    if not out:
        raise AssertionError("no JSON output; stderr was: %s" % err)
    return code, json.loads(out)


class TempTree(object):
    """Mixin: write a dict of {relative path: text} into a temporary directory."""

    def tree(self, files):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        for rel, text in files.items():
            target = root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text if isinstance(text, str) else json.dumps(text), encoding="utf-8")
        return root

    def scan_tree(self, files, *flags):
        return scan(self.tree(files), *flags)[1]

    def checks(self, files):
        """Sorted "check resource" strings for the findings in a tree."""
        return sorted("%s %s" % (f["check"], f["resource"]) for f in self.scan_tree(files)["findings"])

    def skipped(self, files):
        """Sorted "check resource" strings for the not-evaluated notes in a tree."""
        return sorted("%s %s" % (n["check"], n["resource"]) for n in self.scan_tree(files)["not_evaluated"])
