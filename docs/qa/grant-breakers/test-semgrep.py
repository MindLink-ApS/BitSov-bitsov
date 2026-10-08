#!/usr/bin/env python3
"""Run breaker rule fixtures with the installed semgrep executable.

Usage: python3 docs/qa/grant-breakers/test-semgrep.py [path-to-semgrep]
Rule path filters are removed only for these intentionally unsafe fixtures.
"""
import pathlib
import subprocess
import sys
import tempfile

here = pathlib.Path(__file__).resolve().parent
source = (here.parent / "semgrep-rules.yml").read_text()
blocks = source.split("\n  - id: ")
rules = []
for block in blocks[1:]:
    if block.startswith("bitsov-grant-"):
        rules.append("  - id: " + block.split("\n    paths:")[0])
with tempfile.TemporaryDirectory(prefix="grant-breaker-rules-") as directory:
    root = pathlib.Path(directory)
    (root / "breakers.yml").write_text("rules:\n" + "\n".join(rules))
    (root / "breakers.rs").write_text((here / "semgrep-tests.rs").read_text())
    sys.exit(subprocess.call([sys.argv[1] if len(sys.argv) > 1 else "semgrep", "--test", str(root)]))
