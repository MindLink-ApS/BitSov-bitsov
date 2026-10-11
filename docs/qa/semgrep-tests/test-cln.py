#!/usr/bin/env python3
"""Run CLN Semgrep fixtures, removing production path filters only for fixtures.

Usage: python3 docs/qa/semgrep-tests/test-cln.py [path-to-semgrep]
"""
import pathlib
import subprocess
import sys
import tempfile

here = pathlib.Path(__file__).resolve().parent
source = (here.parent / "semgrep-rules.yml").read_text()
rules = []
for block in source.split("\n  - id: ")[1:]:
    if block.startswith("bitsov-cln-"):
        # Paths can occur before or after the rule body.
        lines = []
        in_paths = False
        for line in ("  - id: " + block).splitlines():
            if line.startswith("    paths:"):
                in_paths = True
                continue
            if in_paths and line.startswith("    ") and not line.startswith("      "):
                in_paths = False
            if not in_paths:
                lines.append(line)
        rules.append("\n".join(lines))
with tempfile.TemporaryDirectory(prefix="cln-rules-") as directory:
    root = pathlib.Path(directory)
    (root / "cln.yml").write_text("rules:\n" + "\n".join(rules))
    (root / "cln.rs").write_text((here / "cln.rs").read_text())
    sys.exit(subprocess.call([sys.argv[1] if len(sys.argv) > 1 else "semgrep", "--test", str(root)]))
