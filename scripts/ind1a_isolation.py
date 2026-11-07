"""감사용 프로세스 경계. 파일/네트워크 sandbox 또는 운영 Worker가 아니다."""
from dataclasses import dataclass
import json
import math
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import tempfile
import time


@dataclass(frozen=True)
class WorkerResult:
    outcome: str
    returncode: int | None
    signal_number: int | None
    stdout_bytes: int
    stderr_bytes: int
    elapsed_ms: float
    reaped: bool
    payload: dict | None = None


MODES = {"analyze", "native_wait", "cpu", "memory", "output", "signal", "nonzero", "invalid", "capabilities", "historical_callback"}
STATUSES = {"ANALYZED", "PARTIAL", "PARSE_ERROR", "RESOURCE_LIMIT", "INVALID_INPUT", "UNAVAILABLE"}
CODES = {"INVALID_INPUT", "PARSE_ERROR", "RESOURCE_LIMIT", "PARSER_UNAVAILABLE", "LOCAL_EVAL_SHADOW",
         "BINDING_REASSIGNED", "AMBIGUOUS_BINDING", "CROSS_FUNCTION_ALIAS", "ALIAS_ORDER_OR_CONTROL_FLOW",
         "UNRESOLVED_CALL", "UNSUPPORTED_CALLEE", "UNSUPPORTED_CONSTRUCT", "ESCAPED_IDENTIFIER",
         "DYNAMIC_BINDING", "ANNEX_B_BINDING"}


def kill_owned_group(process):
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def valid_payload(value, mode, source_length):
    if type(value) is not dict or value.get("version") != "ind1a-worker/v1":
        return False
    limits = value.get("limits")
    if type(limits) is not dict or set(limits) != {"core", "cpu", "address_space", "open_files"}:
        return False
    if any(pair is not None and (type(pair) is not list or len(pair) != 2 or any(type(n) is not int or n < 0 for n in pair)) for pair in limits.values()):
        return False
    base = {"version", "limits"}
    if mode == "analyze":
        return set(value) == base | {"analysis"} and valid_analysis(value["analysis"], source_length)
    if mode == "memory":
        return (set(value) == base | {"memory_limit", "memory_probe", "allocated_mib"}
                and value["memory_limit"] in (None, [64 * 1024**2, 64 * 1024**2])
                and value["memory_probe"] in {"ALLOCATION_REACHED_128_MIB", "ALLOCATION_REFUSED"}
                and type(value["allocated_mib"]) is int and 0 <= value["allocated_mib"] <= 128)
    if mode == "capabilities":
        return (set(value) == base | {"file_read_possible", "loopback_bind_possible", "parent_canary_inherited"}
                and all(type(value[key]) is bool for key in ("file_read_possible", "loopback_bind_possible", "parent_canary_inherited")))
    if mode == "historical_callback":
        return set(value) == base | {"historical_callback"} and value["historical_callback"] == "RETURNED_WITHOUT_CRASH"
    return set(value) == base


def valid_analysis(value, source_length):
    if type(value) is not dict or set(value) != {"status", "kinds", "calls", "bindings", "diagnostics", "verification"}:
        return False
    if value["status"] not in STATUSES:
        return False
    kinds, calls, bindings, diagnostics, verification = (value[key] for key in ("kinds", "calls", "bindings", "diagnostics", "verification"))
    if not all(type(items) is list and len(items) <= 64 for items in (kinds, calls, bindings, diagnostics, verification)):
        return False
    if not len(kinds) == len(calls) == len(bindings) == len(verification):
        return False
    if any(kind not in {"DIRECT_CALL", "SIMPLE_ALIAS_CALL"} for kind in kinds) or any(item != "UNVERIFIED" for item in verification):
        return False
    if any(code not in CODES for code in diagnostics):
        return False
    for kind, call, binding in zip(kinds, calls, bindings):
        if type(call) is not list or len(call) != 2 or any(type(item) is not int for item in call) or not 0 <= call[0] < call[1] <= source_length:
            return False
        if kind == "DIRECT_CALL" and binding is not None:
            return False
        if kind == "SIMPLE_ALIAS_CALL":
            if type(binding) is not list or len(binding) != 4 or any(type(item) is not int for item in binding):
                return False
            if not 0 <= binding[0] <= binding[2] < binding[3] <= binding[1] <= call[0]:
                return False
    return True


def run_worker(source=b"", *, mode="analyze", wall_seconds=3.0, output_limit=16_384, allow_native_repro=False):
    if mode not in MODES or type(source) is not bytes or not 0 < len(source) + 1 <= 131_073:
        raise ValueError("ind1a_worker_input_invalid")
    if type(wall_seconds) not in (int, float) or not math.isfinite(wall_seconds) or not 0.1 <= wall_seconds <= 5:
        raise ValueError("ind1a_wall_invalid")
    if type(output_limit) is not int or not 64 <= output_limit <= 16_384:
        raise ValueError("ind1a_output_limit_invalid")
    if mode == "historical_callback" and not allow_native_repro:
        raise ValueError("ind1a_native_repro_requires_opt_in")
    command = [sys.executable, "-I", "-B", str(Path(__file__).with_name("ind1a_worker.py")), mode]
    if mode == "historical_callback":
        command.append("--allow-native-repro")
    started = time.monotonic()
    output = bytearray()
    counts = {"stdout": 0, "stderr": 0}
    outcome = None
    with tempfile.TemporaryDirectory(prefix="aicsa-ind1a-") as temporary:
        if mode == "capabilities":
            Path(temporary, "probe-data").write_bytes(b"synthetic")
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   cwd=temporary, env={"LANG": "C", "LC_ALL": "C", "PYTHONHASHSEED": "0"},
                                   start_new_session=True, close_fds=True)
        deadline = started + wall_seconds
        try:
            with selectors.DefaultSelector() as selector:
                for stream, label in ((process.stdout, "stdout"), (process.stderr, "stderr")):
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ, label)
                if source:
                    os.set_blocking(process.stdin.fileno(), False)
                    selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
                else:
                    process.stdin.close()
                sent = 0
                while selector.get_map():
                    if time.monotonic() >= deadline:
                        outcome = "WALL_TIMEOUT"
                        break
                    for key, _ in selector.select(min(0.05, max(0, deadline - time.monotonic()))):
                        if key.data == "stdin":
                            try:
                                sent += os.write(key.fd, source[sent:sent + 4096])
                            except BrokenPipeError:
                                sent = len(source)
                            if sent == len(source):
                                selector.unregister(key.fileobj)
                                key.fileobj.close()
                            continue
                        chunk = os.read(key.fd, 4096)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            key.fileobj.close()
                            continue
                        counts[key.data] += len(chunk)
                        if sum(counts.values()) > output_limit:
                            outcome = "OUTPUT_LIMIT"
                            break
                        if key.data == "stdout":
                            output.extend(chunk)
                    if outcome:
                        break
            if outcome:
                kill_owned_group(process)
            try:
                returncode = process.wait(timeout=max(0.1, deadline - time.monotonic()) if not outcome else 1)
            except subprocess.TimeoutExpired:
                outcome = "WALL_TIMEOUT"
                kill_owned_group(process)
                returncode = process.wait(timeout=1)
        finally:
            if process.poll() is None:
                kill_owned_group(process)
                process.wait(timeout=1)
            for stream in (process.stdin, process.stdout, process.stderr):
                stream.close()
    payload = None
    if not outcome:
        if returncode < 0:
            outcome = "SIGNALLED"
        elif returncode != 0:
            outcome = "NONZERO_EXIT"
        else:
            try:
                decoded = json.loads(output)
                valid = valid_payload(decoded, mode, len(source))
                outcome = "RETURNED" if valid else "INVALID_OUTPUT"
                if valid:
                    payload = decoded
            except (ValueError, TypeError):
                outcome = "INVALID_OUTPUT"
    return WorkerResult(outcome, returncode, -returncode if returncode < 0 else None,
                        counts["stdout"], counts["stderr"], round((time.monotonic() - started) * 1000, 3),
                        process.poll() is not None, payload)
