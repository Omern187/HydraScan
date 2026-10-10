#!/usr/bin/env python3
"""HydraScan's local review runner. Python standard library only."""
import argparse
import ast
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone

VERSION = "2026-10-10.8"
SKILL_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
from hydrascan_source import inspect_python, inspect_javascript
EXCLUDED_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".next", ".cache"}
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 100 * 1024 * 1024
MAX_FILES = 10000
MAX_LOG_BYTES = 1024 * 1024
INPUT = "Command, code, and template injection"
CONTENT = "XSS and content injection"
PARSER = "Parsers and serialization"
TRANSPORT = "Cryptography and transport"
PRIVACY = "Data exposure and privacy"
MARK_START = "<!-- hydrascan:generated:start -->"
MARK_END = "<!-- hydrascan:generated:end -->"


def stamp():
    return datetime.now(timezone.utc).isoformat()


def write_json(path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def secret_file(name):
    lower = name.lower()
    return (lower.startswith(".env") and lower not in {".env.example", ".env.sample", ".env.template"}) or lower in {
        "id_rsa", "id_ed25519", ".npmrc", ".pypirc", "credentials", "credentials.json",
    } or lower.endswith((".key", ".pem", ".p12", ".pfx"))


def is_link(path):
    # Includes Windows junctions/reparse points on Python versions without Path.is_junction.
    return path.is_symlink() or bool(getattr(path.lstat(), "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def snapshot(source, destination):
    """Copy bounded text input; never follow links or mount the original source."""
    included, excluded = [], []
    total = 0
    destination.mkdir()

    def walk_error(error):
        path = Path(error.filename) if error.filename else source
        excluded.append({"path": path.relative_to(source).as_posix(), "reason": "directory unreadable: " + type(error).__name__})

    for current, directories, files in os.walk(source, followlinks=False, onerror=walk_error):
        current = Path(current)
        for name in sorted(directories[:]):
            path = current / name
            if is_link(path):
                directories.remove(name)
                excluded.append({"path": path.relative_to(source).as_posix(), "reason": "link"})
            elif name in EXCLUDED_DIRS:
                directories.remove(name)
                excluded.append({"path": path.relative_to(source).as_posix(), "reason": "dependency/cache/VCS directory"})
        directories.sort()
        for name in sorted(files):
            path = current / name
            relative = path.relative_to(source).as_posix()
            reason = None
            try:
                if is_link(path) or not path.is_file():
                    reason = "link or nonregular file"
                elif secret_file(name):
                    reason = "credential file"
                elif len(included) >= MAX_FILES:
                    reason = "file-count limit"
                else:
                    # Bounded read also covers a file growing after its stat.
                    with path.open("rb") as stream:
                        data = stream.read(MAX_FILE_BYTES + 1)
                    if len(data) > MAX_FILE_BYTES:
                        reason = "per-file byte limit"
                    elif b"\0" in data:
                        reason = "binary file"
                    elif total + len(data) > MAX_TOTAL_BYTES:
                        reason = "snapshot byte limit"
                    else:
                        data.decode("utf-8-sig")
                        target = destination / relative
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_bytes(data)
                        included.append({"path": relative, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)})
                        total += len(data)
            except (OSError, UnicodeError) as error:
                reason = "unreadable or non-UTF-8 text: " + type(error).__name__
            if reason:
                excluded.append({"path": relative, "reason": reason})
    fingerprint = hashlib.sha256(json.dumps(included, sort_keys=True).encode()).hexdigest()
    return {"source": str(source), "fingerprint": fingerprint, "files": included, "excluded": excluded, "bytes": total}


def analyze(root, files):
    candidates, gaps, review_tasks = [], [], []

    def add(path, signal):
        line, rule = signal['line'], signal['rule']
        identity = f"{path}:{line}:{rule}"
        candidates.append({"id": "HS-" + hashlib.sha256(identity.encode()).hexdigest()[:12],
                           **signal, "path": path, "kind": "security", "proof_state": "candidate",
                           "proof_gap": "Establish reachable input, effective controls and actual impact; a source signal alone is not a vulnerability."})

    for item in files:
        path = item['path']
        text = (root / path).read_text(encoding='utf-8-sig')
        suffix = Path(path).suffix.lower()
        signals = []
        if suffix == '.py':
            try:
                signals, tasks = inspect_python(text)
                for task in tasks:
                    identity = f"{path}:{task['line']}:{task['rule']}"
                    review_tasks.append({"id": "HR-" + hashlib.sha256(identity.encode()).hexdigest()[:12],
                                         "path": path, "kind": "review-task", **task})
            except SyntaxError as error:
                gaps.append({"path": path, "line": error.lineno,
                             "reason": "Python AST parse failed; inspect the application's supported Python version."})
                continue
        elif suffix in {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.html', '.vue', '.svelte'}:
            signals = inspect_javascript(text, html=suffix in {'.html', '.vue', '.svelte'})
            gaps.append({'path': path, 'line': None, 'reason': 'Lexical/script triage is not a full JS/TS/framework parser: review template interpolation, regex literals, escaped embedded scripts, markup expressions and dynamic dispatch separately.'})
        for signal in signals:
            add(path, signal)
        # Never record matched credentials or code excerpts.
        if suffix in {'.py', '.js', '.ts', '.json', '.yaml', '.yml', '.toml', '.ini'}:
            expression = r"(?i)\b(?:api[_-]?key|access[_-]?token|password|client[_-]?secret)\b[\"']?\s*[:=]\s*[\"']([^\"'\r\n]{12,})[\"']"
            for match in re.finditer(expression, text):
                value = match.group(1)
                if value.startswith(('${', '{{', '<')) or re.search(r'(?i)example|placeholder|your[_-]|changeme', value):
                    continue
                add(path, {"line": text.count('\n', 0, match.start()) + 1, "rule": "embedded-credential",
                           "title": "Possible embedded credential (value withheld)", "family": PRIVACY,
                           "method": "literal triage", "detail": "Establish whether this is a credential and who can obtain it; never test it against an unrelated service."})
    return candidates, gaps, review_tasks


def snapshot_changes(root, files):
    changes = []
    for item in files:
        path = root / item["path"]
        try:
            if not path.exists():
                state = "removed"
            elif is_link(path) or root not in path.resolve().parents:
                state = "replaced with link or escaped path"
            else:
                with path.open("rb") as stream:
                    data = stream.read(MAX_FILE_BYTES + 1)
                state = "modified" if hashlib.sha256(data).hexdigest() != item["sha256"] else None
        except OSError:
            state = "unreadable after checks"
        if state:
            changes.append({"path": item["path"], "state": state})
    return changes


def load_checks(path):
    if path is None:
        return []
    checks = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(checks, list):
        raise ValueError("checks JSON must be a list")
    for check in checks:
        if not isinstance(check, dict) or not isinstance(check.get("name"), str) or not check["name"].strip():
            raise ValueError("each check requires a nonempty name")
        argv = check.get("argv")
        if not isinstance(argv, list) or not argv or not all(isinstance(x, str) and x and "\0" not in x for x in argv):
            raise ValueError("each check requires a nonempty argv list of strings")
        timeout = check.get("timeout", 60)
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not 0 < timeout <= 3600:
            raise ValueError("check timeout must be finite and between 0 and 3600 seconds")
    return checks


def stop_process(process):
    if os.name == "nt":
        # The check worker owns a kill-on-close job, so ending it also ends descendants.
        if process.poll() is None:
            process.kill()
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    if process.poll() is None:
        process.kill()
    process.wait(timeout=10)


def windows_check_job():
    """Assign this worker before launching app code; OS close kills its process tree.

    See https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects
    The handle deliberately stays open until worker process exit (not Python atexit).
    """
    import ctypes
    from ctypes import wintypes

    class BasicLimits(ctypes.Structure):
        _fields_ = [("process_time", ctypes.c_int64), ("job_time", ctypes.c_int64),
                    ("flags", wintypes.DWORD), ("minimum_working_set", ctypes.c_size_t),
                    ("maximum_working_set", ctypes.c_size_t), ("active_process_limit", wintypes.DWORD),
                    ("affinity", ctypes.c_size_t), ("priority_class", wintypes.DWORD), ("scheduling_class", wintypes.DWORD)]

    class IoCounters(ctypes.Structure):
        _fields_ = [(name, ctypes.c_uint64) for name in ("read_ops", "write_ops", "other_ops", "read_bytes", "write_bytes", "other_bytes")]

    class ExtendedLimits(ctypes.Structure):
        _fields_ = [("basic", BasicLimits), ("io", IoCounters), ("process_memory", ctypes.c_size_t),
                    ("job_memory", ctypes.c_size_t), ("peak_process_memory", ctypes.c_size_t), ("peak_job_memory", ctypes.c_size_t)]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel.CreateJobObjectW.restype = wintypes.HANDLE
    kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    kernel.SetInformationJobObject.restype = wintypes.BOOL
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    job = kernel.CreateJobObjectW(None, None)
    if not job:
        raise ctypes.WinError(ctypes.get_last_error())
    limits = ExtendedLimits()
    limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    if not kernel.SetInformationJobObject(job, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
        error = ctypes.get_last_error()
        kernel.CloseHandle(job)
        raise ctypes.WinError(error)
    if not kernel.AssignProcessToJobObject(job, kernel.GetCurrentProcess()):
        error = ctypes.get_last_error()
        kernel.CloseHandle(job)
        raise ctypes.WinError(error)
    return job


def check_worker(status_path, argv):
    try:
        if os.name == "nt":
            job_handle = windows_check_job()
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, check=False)
        write_json(status_path, {"status": "passed" if result.returncode == 0 else "failed", "exit_code": result.returncode})
        return 0
    except OSError as error:
        write_json(status_path, {"status": "error", "exit_code": None, "error": type(error).__name__})
        return 1


def drain_output(stream, captured, flags):
    try:
        while True:
            chunk = stream.read(8192)
            if not chunk:
                break
            remaining = MAX_LOG_BYTES - len(captured)
            captured.extend(chunk[:remaining])
            flags["truncated"] |= len(chunk) > remaining
    finally:
        stream.close()


def redact(text):
    for name, value in os.environ.items():
        if re.search(r"(?i)token|secret|password|api_?key", name) and len(value) >= 4:
            text = text.replace(value, "[REDACTED]")
    return text


def execute_checks(checks, cwd, run):
    results = []
    (run / "logs").mkdir()
    for index, check in enumerate(checks, 1):
        started = time.monotonic()
        result = {"name": check["name"], "status": "error", "exit_code": None, "log": f"logs/check-{index}.log",
                  "argv": [redact(argument) for argument in check["argv"]], "timeout_seconds": check.get("timeout", 60)}
        captured = bytearray()
        flags = {"truncated": False}
        process = None
        status_path = run / "logs" / f"check-{index}-status.json"

        try:
            worker_argv = [sys.executable, str(Path(__file__).resolve()), "_check", str(status_path), *check["argv"]]
            process = subprocess.Popen(worker_argv, cwd=cwd, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       start_new_session=os.name != "nt",
                                       creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0)
            reader = threading.Thread(target=drain_output, args=(process.stdout, captured, flags), daemon=True)
            reader.start()
            try:
                process.wait(timeout=check.get("timeout", 60))
                if status_path.exists():
                    result.update(json.loads(status_path.read_text(encoding="utf-8")))
                else:
                    result["error"] = "Check worker stopped without a result"
                # A successful foreground command may leave background descendants.
                # On Windows the worker's job closes automatically on its exit.
                if os.name != "nt":
                    stop_process(process)
            except subprocess.TimeoutExpired:
                stop_process(process)
                result["status"] = "timeout"
            except KeyboardInterrupt:
                stop_process(process)
                raise
            reader.join(timeout=2)
            if reader.is_alive():
                result["output_incomplete"] = True
            if result["status"] == "timeout":
                result["exit_code"] = process.returncode
        except OSError as error:
            result["error"] = type(error).__name__
        result["duration_seconds"] = round(time.monotonic() - started, 3)
        result["log_truncated"] = flags["truncated"]
        (run / result["log"]).write_text(redact(bytes(captured).decode("utf-8", errors="replace")), encoding="utf-8")
        results.append(result)
        # Preserve completed work if the next command fails or is interrupted.
        write_json(run / "checks.json", results)
    return results


def coverage(candidates, review_tasks=()):
    families = []
    for line in (SKILL_ROOT / "references/coverage.md").read_text(encoding="utf-8").splitlines():
        if line.startswith("| "):
            label = line.split("|")[1].strip()
            if label not in {"Family", "Technology", "---"}:
                families.append(label)
    touched = {x["family"] for x in [*candidates, *review_tasks]}
    return [{"family": label, "status": "partial" if label in touched else "not-started", "owner": "unassigned",
             "method": "source signal triage" if label in touched else "not assessed by native runner",
             "remaining": "Assign agent ownership and validate applicable entrypoints, controls and runtime behavior."}
            for label in families]


def markdown(value):
    text = re.sub(r"[\r\n\x00-\x1f]", " ", str(value)).replace("<", "&lt;").replace(">", "&gt;")
    return re.sub(r"([\\`*_{}\[\]()#!|])", r"\\\1", text)


def update_generated(path, body, notes):
    generated = MARK_START + "\n" + body + "\n" + MARK_END
    if path.exists():
        text = path.read_text(encoding="utf-8")
        if text.count(MARK_START) != 1 or text.count(MARK_END) != 1:
            raise ValueError(f"{path.name}: generated markers missing or duplicated; preserve this file and repair markers")
        start, end = text.index(MARK_START), text.index(MARK_END) + len(MARK_END)
        if start >= text.index(MARK_END):
            raise ValueError(f"{path.name}: generated markers are reversed; preserve this file and repair markers")
        text = text[:start] + generated + text[end:]
    else:
        text = generated + "\n\n" + notes + "\n"
    path.write_text(text, encoding="utf-8")


def collect(run):
    metadata = json.loads((run / "run.json").read_text(encoding="utf-8"))
    inventory = json.loads((run / "inventory.json").read_text(encoding="utf-8"))
    candidates = json.loads((run / "candidates.json").read_text(encoding="utf-8"))
    checks = json.loads((run / "checks.json").read_text(encoding="utf-8"))
    gaps = json.loads((run / "analysis-gaps.json").read_text(encoding="utf-8"))
    tasks_path = run / "security-review-tasks.json"
    tasks = json.loads(tasks_path.read_text(encoding="utf-8")) if tasks_path.exists() else []
    changes = json.loads((run / "snapshot-changes.json").read_text(encoding="utf-8"))
    body = ["# HydraScan local triage", "", f"Run status: {metadata['status']}. Updated: {stamp()}.",
            f"Source fingerprint: `{inventory['fingerprint']}`.",
            f"Text files copied: {len(inventory['files'])}; exclusions: {len(inventory['excluded'])}; parse gaps: {len(gaps)}.",
            f"Inventoried files changed by check execution: {len(changes)}. Static signals refer to the initial snapshot.",
            f"Candidate signals: {len(candidates)}. Confirmed vulnerabilities: not determined by this runner.", "",
            f"Semantic security review tasks: {len(tasks)}. These are questions, not detected vulnerabilities.", "", "## Candidate signals", "", "| ID | Location | Signal | Proof |", "| --- | --- | --- | --- |"]
    for item in candidates:
        body.append(f"| {markdown(item['id'])} | {markdown(item['path'])}:{item['line']} | {markdown(item['title'])} | candidate |")
    if not candidates:
        body.append("| — | — | No supported source signals observed | Broader review still required |")
    body += ["", "## Semantic security review tasks", "", "| Location | Required review |", "| --- | --- |"]
    for task in tasks:
        body.append(f"| {markdown(task['path'])}:{task['line']} | {markdown(task['question'])} |")
    if not tasks:
        body.append("| — | No recognized ownership review tasks; policy coverage still requires agent review |")
    body += ["", "## Application checks", "", "| Check | Result | Exit code | Log |", "| --- | --- | --- | --- |"]
    for item in checks:
        body.append(f"| {markdown(item['name'])} | {markdown(item['status'])} | {item['exit_code']} | {markdown(item['log'])} |")
    if not checks:
        body.append("| — | not-run | — | No explicit check commands supplied |")
    body += ["", "## Coverage limits", "",
             "Signals cover selected local Python assignment flows and JavaScript/TypeScript/HTML lexical patterns only. They are hypotheses, not reachability or exploit proof.",
             "Command success does not establish app correctness or security. Review inventory.json exclusions and analysis-gaps.json before interpreting results.",
             "No live targets, authorization flows, package advisories or production builds were tested automatically. Agent-owned coverage and independent validation are still required."]
    update_generated(run / "report.md", "\n".join(body), "## Validated agent findings\n\nRecord evidence-backed findings here, outside the generated markers.")
    state = f"# HydraScan checkpoint\n\nRun status: {metadata['status']}.\nFingerprint: `{inventory['fingerprint']}`.\nNative candidates: {len(candidates)}. Open semantic review questions: {len(tasks)}. Completed check commands: {len(checks)}.\n\nRead coverage.json and report.md. Assign unowned families; review exclusions and parse gaps; independently validate consequential candidates. Do not equate an empty candidate list with a clean assessment."
    update_generated(run / "review-state.md", state, "## Agent ownership and continuation\n\nRecord lane owners, evidence, validated/invalidated candidates, resources and next actions here.")
    return {"run": str(run), "status": metadata["status"], "candidates": len(candidates), "review_tasks": len(tasks), "checks": len(checks), "report": str(run / "report.md")}


def scan(source, run, checks_path=None):
    source, run = source.resolve(), run.resolve()
    if not source.is_dir():
        raise ValueError("source must be an existing directory")
    if run == source or source in run.parents or run in source.parents:
        raise ValueError("run directory must be separate from and outside the source tree")
    checks = load_checks(checks_path)
    run.mkdir(parents=True, exist_ok=False)
    metadata = {"version": VERSION, "created": stamp(), "status": "running", "source": str(source),
                "snapshot": "snapshot", "network_testing": "not performed by runner"}
    write_json(run / "run.json", metadata)
    inventory = None
    try:
        inventory = snapshot(source, run / "snapshot")
        write_json(run / "inventory.json", inventory)
        candidates, gaps, tasks = analyze(run / "snapshot", inventory["files"])
        write_json(run / "candidates.json", candidates)
        write_json(run / "analysis-gaps.json", gaps)
        write_json(run / "security-review-tasks.json", tasks)
        write_json(run / "coverage.json", coverage(candidates, tasks))
        write_json(run / "checks.json", [])
        write_json(run / "snapshot-changes.json", [])
        execute_checks(checks, run / "snapshot", run)
        metadata["status"] = "completed"
    except BaseException as error:
        metadata["status"] = "interrupted" if isinstance(error, KeyboardInterrupt) else "error"
        metadata["error_type"] = type(error).__name__
        raise
    finally:
        if inventory is not None:
            write_json(run / "snapshot-changes.json", snapshot_changes(run / "snapshot", inventory["files"]))
        metadata["updated"] = stamp()
        write_json(run / "run.json", metadata)
    return collect(run)


def main(argv=None):
    parser = argparse.ArgumentParser(description="HydraScan independent local review runner (no external security engine).")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("doctor", help="show runtime availability; performs no installs or scans")
    review = commands.add_parser("scan", help="copy bounded source, triage signals and run explicitly supplied checks")
    review.add_argument("source", type=Path)
    review.add_argument("--output", required=True, type=Path, help="new run directory outside source")
    review.add_argument("--checks", type=Path, help="explicit JSON list of authorized argv commands")
    report = commands.add_parser("collect", help="refresh generated reports while retaining agent notes")
    report.add_argument("run", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "doctor":
            result = {"version": VERSION, "python": sys.version.split()[0], "ready": sys.version_info >= (3, 10),
                      "external_engine_required": False, "extra_packages_required": [],
                      "agent_execution": "provided by the host; runner does not spawn model agents"}
        elif args.command == "scan":
            result = scan(args.source, args.output, args.checks)
        else:
            result = collect(args.run.resolve())
        print(json.dumps(result, ensure_ascii=False))
        return 0
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as error:
        print(f"HydraScan: {type(error).__name__}: operation could not complete; inspect inputs and saved run status.", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("HydraScan: interrupted; completed check results are preserved.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    if len(sys.argv) >= 4 and sys.argv[1] == "_check":
        raise SystemExit(check_worker(Path(sys.argv[2]), sys.argv[3:]))
    raise SystemExit(main())
