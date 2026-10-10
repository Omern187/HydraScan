"""Optional, bounded Babel source analysis. No application code is executed.

Install the pinned parser in scripts/javascript-parser, or point
HYDRASCAN_JS_PARSER_ROOT at an isolated directory containing node_modules.
Missing parsers and rejected files retain lexical triage with explicit gaps.
"""
import importlib.util
import json
import math
import os
from pathlib import Path
import shutil
import subprocess

SCRIPT = Path(__file__).with_name("hydrascan_js_ast.cjs")
PARSER_ROOT = Path(__file__).with_name("javascript-parser")
METHOD = "JavaScript Babel AST and bounded local/module call flow"


def _options(node=None, parser_root=None, timeout=20, max_source_bytes=1_000_000,
             max_total_bytes=8_000_000, max_nodes=150_000, max_call_depth=8):
    bounds = (timeout, max_source_bytes, max_total_bytes, max_nodes, max_call_depth)
    if any(isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0 for value in bounds):
        raise ValueError("JavaScript resource bounds must be finite positive numbers")
    return {"node": str(node or os.environ.get("HYDRASCAN_NODE") or shutil.which("node") or "node"),
            "parser_root": str(parser_root or os.environ.get("HYDRASCAN_JS_PARSER_ROOT") or PARSER_ROOT),
            "timeout": min(timeout, 120), "max_source_bytes": int(min(max_source_bytes, 4_000_000)),
            "max_total_bytes": int(min(max_total_bytes, 32_000_000)),
            "max_nodes": int(min(max_nodes, 500_000)), "max_call_depth": int(min(max_call_depth, 16))}


def _run(payload, options):
    # Explicit parser root prevents loading reviewed applications' packages/configuration.
    environment = dict(os.environ)
    environment.pop("NODE_OPTIONS", None)
    environment.pop("NODE_PATH", None)
    payload["parser_root"] = options["parser_root"]
    result = subprocess.run([options["node"], "--max-old-space-size=256", str(SCRIPT)],
                            input=json.dumps(payload), text=True, encoding="utf-8", errors="replace",
                            capture_output=True, timeout=options["timeout"], env=environment)
    if result.returncode:
        raise RuntimeError("AST process failed (exit %s)" % result.returncode)
    if len(result.stdout) > 12_000_000:
        raise RuntimeError("AST response exceeded output bound")
    response = json.loads(result.stdout)
    if not isinstance(response, dict) or response.get("schema_version") != 1:
        raise ValueError("invalid AST response schema")
    return response


def doctor(*, node=None, parser_root=None, timeout=10):
    """Read-only availability check; does not install dependencies."""
    options = _options(node=node, parser_root=parser_root, timeout=timeout)
    try:
        response = _run({"action": "doctor", "schema_version": 1}, options)
        return {"available": bool(response.get("available")), "method": METHOD,
                "parser": "@babel/parser", "version": response.get("version"),
                "node": options["node"], "parser_root": options["parser_root"],
                "detail": response.get("detail", "")}
    except (OSError, subprocess.SubprocessError, ValueError, RuntimeError) as error:
        return {"available": False, "method": METHOD, "parser": "@babel/parser",
                "node": options["node"], "parser_root": options["parser_root"],
                "detail": str(error)}


def _gap(path, rule, detail, backend="lexical-fallback"):
    return {"path": path, "line": 1, "column": 1, "rule": rule,
            "title": "JavaScript AST coverage gap", "family": "Source analysis coverage",
            "method": METHOD, "backend": backend, "detail": detail, "trace": []}


def _source_module():
    spec = importlib.util.spec_from_file_location("hydrascan_js_lexical", Path(__file__).with_name("hydrascan_source.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _script_sources(sources):
    """Blank HTML markup while preserving script line and column offsets."""
    module = _source_module()
    prepared = {}
    for path, source in sources.items():
        if Path(path).suffix.lower() in {".html", ".htm", ".vue", ".svelte"}:
            masked = [char if char in "\r\n\u2028\u2029" else " " for char in source]
            for offset, script in module.script_regions(source):
                masked[offset:offset + len(script)] = script
            prepared[path] = "".join(masked)
        else:
            prepared[path] = source
    return prepared


def _lexical(sources):
    module = _source_module()
    signals = []
    for path, source in sources.items():
        for item in module.inspect_javascript(source, html=Path(path).suffix.lower() in {".html", ".htm", ".vue", ".svelte"}):
            signals.append({**item, "path": path, "column": item.get("column", 1), "trace": [],
                            "backend": "lexical-fallback", "proof_state": "candidate",
                            "detail": item["detail"] + " AST unavailable for this file; lexical fallback is incomplete."})
    return signals


def inspect_project(sources, *, node=None, parser_root=None, timeout=20,
                    max_source_bytes=1_000_000, max_total_bytes=8_000_000,
                    max_nodes=150_000, max_call_depth=8):
    """Return (signals, gaps, tasks), all per-path candidate/review evidence.

    Sources are strings keyed by project-relative paths. No source paths are read,
    no project packages are imported, and no source strings are evaluated.
    """
    if not isinstance(sources, dict) or any(not isinstance(p, str) or not isinstance(s, str) for p, s in sources.items()):
        raise TypeError("sources must be a dict of path strings to source strings")
    options = _options(node, parser_root, timeout, max_source_bytes, max_total_bytes, max_nodes, max_call_depth)
    accepted, gaps, total = {}, [], 0
    for path, source in sources.items():
        size = len(source.encode("utf-8"))
        if size > options["max_source_bytes"] or total + size > options["max_total_bytes"] or len(accepted) >= 2000:
            gaps.append(_gap(path, "js-resource-bound", "Source excluded by file/project byte or file-count bound; no fallback was run on excluded source.", backend="none"))
        else:
            accepted[path] = source
            total += size
    if not accepted:
        return [], gaps, []
    try:
        response = _run({"schema_version": 1, "sources": _script_sources(accepted),
                         "limits": {key: options[key] for key in ("max_nodes", "max_call_depth")}}, options)
        if not response.get("available"):
            raise RuntimeError(response.get("detail", "optional Babel parser unavailable"))
        for key in ("signals", "gaps", "tasks"):
            if not isinstance(response.get(key), list):
                raise ValueError("invalid AST evidence arrays")
            for item in response[key]:
                if (not isinstance(item, dict) or item.get("path") not in accepted
                        or any(not isinstance(item.get(field), str) for field in ("rule", "title", "family", "method", "detail"))
                        or not isinstance(item.get("line"), int) or item["line"] < 1
                        or not isinstance(item.get("column"), int) or item["column"] < 1
                        or not isinstance(item.get("trace"), list)):
                    raise ValueError("invalid AST evidence item")
        fallback_paths = response.get("fallback_paths", [])
        if not isinstance(fallback_paths, list) or any(path not in accepted for path in fallback_paths):
            raise ValueError("invalid AST fallback paths")
        fallback = _lexical({path: accepted[path] for path in fallback_paths})
        for signal in response["signals"]:
            signal["proof_state"] = "candidate"
        for path in accepted:
            if Path(path).suffix.lower() in {".html", ".htm", ".vue", ".svelte"}:
                gaps.append(_gap(path, "js-embedded-markup-coverage", "Only executable script elements were analyzed. Markup expressions, inline handlers, component/template policy and separate script execution contexts require review.", backend="babel-ast"))
        return response["signals"] + fallback, gaps + response["gaps"], response["tasks"]
    except (OSError, subprocess.SubprocessError, ValueError, RuntimeError) as error:
        rule = "js-ast-timeout" if isinstance(error, subprocess.TimeoutExpired) else "js-ast-unavailable"
        gaps.extend(_gap(path, rule, str(error) + "; only lexical triage was available.") for path in accepted)
        return _lexical(accepted), gaps, []
