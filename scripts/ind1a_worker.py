"""IND-1A 시험 전용 자식. JavaScript를 실행하지 않으며 제품 경로에서 사용하지 않는다."""
import json
import os
from pathlib import Path
import resource
import signal
import sys


def apply_limit(kind, values):
    try:
        resource.setrlimit(kind, values)
        return list(resource.getrlimit(kind))
    except (ValueError, OSError):
        return None


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    # 네이티브 모듈을 import하기 전에 적용한다. 설정 성공과 실제 강제는 다르다.
    limits = {
        "core": apply_limit(resource.RLIMIT_CORE, (0, 0)),
        "cpu": apply_limit(resource.RLIMIT_CPU, (1, 2)),
        "address_space": apply_limit(resource.RLIMIT_AS, (512 * 1024**2, 512 * 1024**2)),
        "open_files": apply_limit(resource.RLIMIT_NOFILE, (64, 64)),
    }
    if limits["core"] != [0, 0]:
        raise ValueError("core_limit_unavailable")
    payload = {"version": "ind1a-worker/v1", "limits": limits}
    if mode == "analyze":
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
        from ai_code_security_analyzer.research.independent_eval import analyze_javascript
        source = sys.stdin.buffer.read(131_073)
        result = analyze_javascript(source, "audit.js")
        payload["analysis"] = {
            "status": result.status.value,
            "kinds": [item.kind for item in result.observations],
            "calls": [[item.call.start_byte, item.call.end_byte] for item in result.observations],
            "bindings": [None if item.alias_declaration is None else
                         [item.alias_declaration.start_byte, item.alias_declaration.end_byte,
                          item.eval_reference.start_byte, item.eval_reference.end_byte]
                         for item in result.observations],
            "diagnostics": [item.code.value for item in result.diagnostics],
            "verification": [item.verification_status for item in result.observations],
        }
    elif mode == "native_wait":
        # Python의 협력적 체크를 거치지 않는 C 호출도 부모가 끝내는지 확인한다.
        import ctypes
        ctypes.CDLL(None).sleep(30)
    elif mode == "cpu":
        while True:
            pass
    elif mode == "memory":
        payload["memory_limit"] = apply_limit(resource.RLIMIT_AS, (64 * 1024**2, 64 * 1024**2))
        chunks = []
        try:
            # macOS에서 제한이 작동하지 않아도 추가 할당은 128 MiB로 끝낸다.
            for _ in range(128):
                chunks.append(bytearray(1024**2))
            payload["memory_probe"] = "ALLOCATION_REACHED_128_MIB"
        except MemoryError:
            payload["memory_probe"] = "ALLOCATION_REFUSED"
        payload["allocated_mib"] = len(chunks)
    elif mode == "output":
        while True:
            os.write(1, b"SYNTHETIC_OUTPUT_CANARY" * 128)
    elif mode == "signal":
        os.kill(os.getpid(), signal.SIGTERM)
    elif mode == "nonzero":
        raise SystemExit(7)
    elif mode == "invalid":
        print("{}")
        return
    elif mode == "capabilities":
        import socket
        payload["file_read_possible"] = Path("probe-data").read_bytes() == b"synthetic"
        with socket.socket() as connection:
            connection.bind(("127.0.0.1", 0))
            payload["loopback_bind_possible"] = True
        payload["parent_canary_inherited"] = "IND1A_ENV_CANARY" in os.environ
    elif mode == "historical_callback" and sys.argv[2:] == ["--allow-native-repro"]:
        from tree_sitter import Language, Parser
        import tree_sitter_javascript
        source = b"function f(x){{let eval=other;eval(x);}eval(x);}"
        Parser(Language(tree_sitter_javascript.language())).parse(
            lambda offset, _point: source[offset:offset + 4096], progress_callback=lambda *_: False)
        payload["historical_callback"] = "RETURNED_WITHOUT_CRASH"
    else:
        raise ValueError("worker_mode_invalid")
    print(json.dumps(payload, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # 자유형 예외·절대 경로·원문은 진단 스트림에 내보내지 않는다.
        print("ind1a_worker_failed", file=sys.stderr)
        raise SystemExit(3)
