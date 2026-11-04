"""Regression guard for the 2.3.0 Monitoring-page crash: a route function named `health` shadowed the imported `health` module,
so /api/health/detail raised AttributeError. These checks need no web framework and run everywhere."""
import ast
import glob
import os

from tests.conftest import ROOT


def collisions(path):
    tree = ast.parse(open(path, encoding="utf-8").read())
    imported, defined = {}, {}
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for a in node.names:
                imported[(a.asname or a.name).split(".")[0]] = node.lineno
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            defined.setdefault(node.name, []).append(node.lineno)
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    defined.setdefault(t.id, []).append(node.lineno)
    return sorted((n, imported[n], defined[n]) for n in imported if n in defined)


def test_no_module_shadows_one_of_its_own_imports():
    bad = {os.path.basename(f): c for f in sorted(glob.glob(str(ROOT / "emailshield" / "*.py"))) if (c := collisions(f))}
    assert bad == {}, f"imported name redefined at module level (this causes AttributeError at request time): {bad}"


def test_the_guard_actually_detects_the_original_bug(tmp_path):
    bug = tmp_path / "bug.py"
    bug.write_text("from . import health\n\n\ndef health():\n    return {'status': 'ok'}\n\n\ndef detail():\n    return health.run_checks()\n")
    assert collisions(bug) == [("health", 1, [4])]
    fixed = tmp_path / "fixed.py"
    fixed.write_text("from . import health as health_checks\n\n\ndef health():\n    return {'status': 'ok'}\n\n\ndef detail():\n    return health_checks.run_checks()\n")
    assert collisions(fixed) == []


def test_app_uses_the_aliased_health_module_and_keeps_the_health_route():
    src = (ROOT / "emailshield" / "app.py").read_text(encoding="utf-8")
    assert "from . import health as health_checks" in src and "health_checks.run_checks()" in src
    assert "health.run_checks()" not in src.replace("health_checks.run_checks()", "")
    assert '@app.get("/api/health")\ndef health():' in src  # the existing endpoint is preserved
