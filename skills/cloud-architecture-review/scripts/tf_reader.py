#!/usr/bin/env python3
"""Read the block structure of Terraform files (.tf, .tfvars) without Terraform.

This is a careful brace-matching reader. It is not a full HCL parser. It reads
blocks, nested blocks and attributes, and records the line of each. It
evaluates literal values only: strings without interpolation, numbers,
booleans, null, and lists and maps built from those.

Everything else is returned as "not evaluated", with its source text:
references (var.x, local.x, module.x, other resources), function calls,
conditionals, for expressions and strings containing ${...}. Heredocs are
also "not evaluated", and their text is left out of that source text. The
reader never substitutes a variable default and never opens a module.

Run it on a file to see exactly what the reader saw:

Examples:
  tf_reader.py main.tf                  # structure; string values hidden
  tf_reader.py main.tf --values         # also show literal string values
  tf_reader.py main.tf prod.tfvars --json

String values are hidden unless --values is given, so that a secret written
in a file is not copied into a terminal log.

Exit codes: 0 = every file was read, 1 = at least one file has syntax the
reader could not follow, 2 = usage error or a file that cannot be opened.
Standard library only. Reads files only. Makes no network calls.
"""
import argparse
import bisect
import json
import re
import sys

IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*")
NUMBER_RE = re.compile(r"-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?$")
HEREDOC_RE = re.compile(r"<<-?([A-Za-z_][A-Za-z0-9_]*)[ \t]*\r?\n")
HEREDOC_BODY_RE = re.compile(
    r"<<-?([A-Za-z_][A-Za-z0-9_]*)[ \t]*\r?\n.*?\n[ \t]*\1[ \t]*(?=\r?\n|$)", re.S)
ESCAPES = {"n": "\n", "t": "\t", "r": "\r"}


class ReadError(Exception):
    """The text has structure this reader cannot follow."""

    def __init__(self, message, line):
        Exception.__init__(self, "line %d: %s" % (line, message))
        self.line = line


class Unknown(object):
    """An expression the reader did not evaluate. Never treat it as a value."""

    def __init__(self, raw):
        self.raw = raw

    def __repr__(self):
        return "Unknown(%r)" % self.raw


class Attr(object):
    """One `name = expression` line, with its literal value or Unknown."""

    def __init__(self, name, raw, line):
        self.name, self.raw, self.line = name, raw, line
        self.value = evaluate(raw)


class Block(object):
    """One `type "label" { ... }` block. The file itself is a Block of type None."""

    def __init__(self, type_, labels, line):
        self.type, self.labels, self.line = type_, labels, line
        self.attrs = {}
        self.blocks = []


class _Scanner(object):
    def __init__(self, text):
        self.text = text
        self.line_starts = [0] + [m.end() for m in re.finditer("\n", text)]

    def line(self, pos):
        return bisect.bisect_right(self.line_starts, pos)

    def error(self, message, pos):
        raise ReadError(message, self.line(pos))

    def skip_comment(self, i):
        """If a comment starts at i, return the index after it, else None.
        A line comment ends before its newline."""
        text = self.text
        if text[i] == "#" or text.startswith("//", i):
            end = text.find("\n", i)
            return len(text) if end == -1 else end
        if text.startswith("/*", i):
            end = text.find("*/", i + 2)
            if end == -1:
                self.error("comment opened with /* is not closed", i)
            return end + 2
        return None

    def skip_string(self, i):
        """i is at an opening quote. Return the index after the closing quote."""
        text, j = self.text, i + 1
        while j < len(text):
            char = text[j]
            if char == "\\":
                j += 2
            elif char == '"':
                return j + 1
            elif char == "\n":
                break
            elif text.startswith("$${", j) or text.startswith("%%{", j):
                j += 3  # escaped: a literal ${ or %{
            elif char in "$%" and text.startswith("{", j + 1):
                j = self.skip_template(j + 2)
            else:
                j += 1
        self.error("string is not closed", i)

    def skip_template(self, i):
        """i is just after ${ or %{. Return the index after the matching brace."""
        text, j, depth = self.text, i, 1
        while j < len(text):
            char = text[j]
            if char == '"':
                j = self.skip_string(j)
                continue
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return j + 1
            j += 1
        self.error("${ ... } inside a string is not closed", i)

    def skip_heredoc(self, i):
        """If a heredoc (<<EOT or <<-EOT) starts at i, return the index after
        its end marker, else None."""
        match = HEREDOC_RE.match(self.text, i)
        if not match:
            return None
        text, pos = self.text, match.end()
        while pos < len(text):
            end = text.find("\n", pos)
            end = len(text) if end == -1 else end
            if text[pos:end].strip() == match.group(1):
                return end
            pos = end + 1
        self.error("heredoc <<%s is not closed" % match.group(1), i)

    def skip_space(self, i, newlines):
        text = self.text
        blank = " \t\r\n" if newlines else " \t\r"
        while i < len(text):
            if text[i] in blank:
                i += 1
                continue
            after = self.skip_comment(i) if text[i] in "#/" else None
            if after is None:
                break
            i = after
        return i

    def read_expression(self, i):
        """Read from i to the end of the expression. Return (text, end index).
        The expression ends at a newline, or at the closing brace of a
        one-line block, outside every bracket, string and heredoc."""
        text, start, depth, parts = self.text, i, 0, []
        while i < len(text):
            char = text[i]
            if char == '"':
                j = self.skip_string(i)
            elif char == "<" and self.skip_heredoc(i) is not None:
                j = self.skip_heredoc(i)
            elif char in "#/" and self.skip_comment(i) is not None:
                i = self.skip_comment(i)
                continue
            else:
                if char in "([{":
                    depth += 1
                elif char in ")]}":
                    if depth == 0 and char == "}":
                        break
                    if depth == 0:
                        self.error("unexpected %r" % char, i)
                    depth -= 1
                elif char == "\n" and depth == 0:
                    break
                j = i + 1
            parts.append(text[i:j])
            i = j
        if depth:
            self.error("bracket opened in this expression is not closed", start)
        return "".join(parts).strip(), i

    def read_body(self, i, block):
        """Read attributes and nested blocks into block, up to its closing
        brace (or the end of the file for the root). Return the index after."""
        text = self.text
        while True:
            i = self.skip_space(i, True)
            if i >= len(text):
                if block.type is not None:
                    raise ReadError("block %r opened here is not closed" % block.type, block.line)
                return i
            if text[i] == "}":
                if block.type is None:
                    self.error("unexpected }", i)
                return i + 1
            match = IDENT_RE.match(text, i)
            if not match:
                self.error("expected a name, found %r" % text[i], i)
            name, start = match.group(0), i
            i = self.skip_space(match.end(), False)
            if text.startswith("=", i) and not text.startswith("==", i):
                raw, i = self.read_expression(i + 1)
                block.attrs[name] = Attr(name, raw, self.line(start))
                continue
            labels = []
            while i < len(text) and text[i] != "{":
                if text[i] == '"':
                    j = self.skip_string(i)
                    labels.append(text[i + 1:j - 1])
                else:
                    match = IDENT_RE.match(text, i)
                    if not match:
                        self.error("expected '=' or '{' after %r" % name, i)
                    labels.append(match.group(0))
                    j = match.end()
                i = self.skip_space(j, False)
            if i >= len(text):
                self.error("expected '{' after %r" % name, start)
            child = Block(name, labels, self.line(start))
            i = self.read_body(i + 1, child)
            block.blocks.append(child)


def _unknown(raw):
    """Unknown, with heredoc bodies left out so they never reach a message or a log."""
    return Unknown(HEREDOC_BODY_RE.sub(r"<<\1 (heredoc text not shown)", raw))


def _enclosed(raw):
    """Return the text inside raw's outer brackets, or None if the opening
    bracket does not close at the very end (as in `[a, b][0]`)."""
    scanner, depth, i = _Scanner(raw), 0, 0
    while i < len(raw):
        char = raw[i]
        if char == '"':
            i = scanner.skip_string(i)
            continue
        if char == "<" and scanner.skip_heredoc(i) is not None:
            i = scanner.skip_heredoc(i)
            continue
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
            if depth == 0 and i != len(raw) - 1:
                return None
        i += 1
    return raw[1:-1] if depth == 0 else None


def _split_top(text, separators, first_only=False):
    """Split text at separator characters outside strings, heredocs and brackets."""
    scanner, depth, i, start, pieces = _Scanner(text), 0, 0, 0, []
    while i < len(text):
        char = text[i]
        if char == '"':
            i = scanner.skip_string(i)
            continue
        if char == "<" and scanner.skip_heredoc(i) is not None:
            i = scanner.skip_heredoc(i)
            continue
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif depth == 0 and char in separators:
            pieces.append(text[start:i])
            start = i + 1
            if first_only:
                break
        i += 1
    pieces.append(text[start:])
    return [piece.strip() for piece in pieces]


def _string(raw):
    if _Scanner(raw).skip_string(0) != len(raw):
        return _unknown(raw)  # e.g. "a" == "b"
    inner = raw[1:-1]
    plain = inner.replace("$${", "").replace("%%{", "")
    if "${" in plain or "%{" in plain or re.search(r"\\[uU]", inner):
        return _unknown(raw)
    inner = inner.replace("$${", "${").replace("%%{", "%{")
    return re.sub(r"\\(.)", lambda m: ESCAPES.get(m.group(1), m.group(1)), inner)


def _map(raw, inner):
    result = {}
    for entry in _split_top(inner, ",\n"):
        if not entry:
            continue
        pair = _split_top(entry, "=:", first_only=True)
        if len(pair) != 2 or pair[1].startswith(("=", ">")):
            return _unknown(raw)
        key = pair[0] if IDENT_RE.fullmatch(pair[0]) else evaluate(pair[0])
        if not isinstance(key, str):
            return _unknown(raw)
        result[key] = evaluate(pair[1])
    return result


def evaluate(raw):
    """Return the literal value of an expression, or Unknown for anything else."""
    raw = raw.strip()
    if raw in ("true", "false"):
        return raw == "true"
    if raw == "null":
        return None
    if NUMBER_RE.match(raw):
        return float(raw) if re.search(r"[.eE]", raw) else int(raw)
    try:
        if raw.startswith('"'):
            return _string(raw)
        if raw[:1] in "[{" and raw[-1:] in "]}":
            inner = _enclosed(raw)
            if inner is None or re.match(r"\s*for\b", inner):
                return _unknown(raw)
            if raw[0] == "{":
                return _map(raw, inner)
            return [evaluate(item) for item in _split_top(inner, ",") if item]
    except ReadError:
        pass
    return _unknown(raw)


def read_text(text):
    """Return the root Block of Terraform source text. Raises ReadError."""
    if text.startswith("﻿"):
        text = text[1:]
    root = Block(None, [], 1)
    _Scanner(text).read_body(0, root)
    return root


def read_file(path):
    with open(path, encoding="utf-8", errors="replace") as handle:
        return read_text(handle.read())


def brief(raw, limit=100):
    """One-line form of an expression for messages."""
    text = " ".join(raw.split())
    return text if len(text) <= limit else text[:limit - 3] + "..."


def plain(value, show_strings):
    """Convert a value to JSON-ready data."""
    if isinstance(value, Unknown):
        return {"not_evaluated": brief(value.raw)}
    if isinstance(value, str) and not show_strings:
        return "<string, %d chars>" % len(value)
    if isinstance(value, list):
        return [plain(item, show_strings) for item in value]
    if isinstance(value, dict):
        return dict((key, plain(item, show_strings)) for key, item in value.items())
    return value


def block_to_dict(block, show_strings):
    return {
        "type": block.type,
        "labels": block.labels,
        "line": block.line,
        "attributes": dict(
            (name, {"line": attr.line, "value": plain(attr.value, show_strings)})
            for name, attr in block.attrs.items()),
        "blocks": [block_to_dict(child, show_strings) for child in block.blocks],
    }


def _print_block(data, indent):
    pad = "  " * indent
    for name in sorted(data["attributes"]):
        value = data["attributes"][name]["value"]
        if isinstance(value, dict) and list(value) == ["not_evaluated"]:
            print("%s%s = NOT EVALUATED: %s" % (pad, name, value["not_evaluated"]))
        else:
            print("%s%s = %s" % (pad, name, json.dumps(value, sort_keys=True)))
    for child in data["blocks"]:
        labels = "".join(' "%s"' % label for label in child["labels"])
        print("%s%s%s  (line %d)" % (pad, child["type"], labels, child["line"]))
        _print_block(child, indent + 1)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("files", nargs="+", metavar="FILE", help="a .tf or .tfvars file")
    parser.add_argument("--json", action="store_true", help="print JSON")
    parser.add_argument("--values", action="store_true",
                        help="show literal string values (hidden by default)")
    args = parser.parse_args(argv)

    results, unreadable = [], 0
    for path in args.files:
        try:
            root = read_file(path)
        except (IOError, OSError) as exc:
            print("tf_reader.py: cannot open %s: %s" % (path, exc.strerror or exc), file=sys.stderr)
            return 2
        except ReadError as exc:
            results.append({"file": path, "error": str(exc)})
            unreadable += 1
            continue
        entry = block_to_dict(root, args.values)
        results.append({"file": path, "attributes": entry["attributes"], "blocks": entry["blocks"]})

    if args.json:
        print(json.dumps(results, indent=2, sort_keys=True))
    else:
        for entry in results:
            print(entry["file"])
            if "error" in entry:
                print("  NOT READ: %s" % entry["error"])
            else:
                _print_block(entry, 1)
    return 1 if unreadable else 0


if __name__ == "__main__":
    sys.exit(main())
