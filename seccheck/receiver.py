"""
Minimal gVisor SecCheck receiver + Discord Notification
Requires: Debian package python3-protobuf. Linux only, AF_UNIX SOCK_SEQPACKET.
Uses official SecCheck protobuf field numbers and wire protocol v1.
"""

import json
import time
import urllib.request
from pathlib import Path

import os
import signal
import socket
import struct
import sys
import threading
from google.protobuf import descriptor_pb2 as d
from google.protobuf import descriptor_pool, message_factory

WEBHOOK = Path("/root/seccheck/discord-webhook").read_text().strip()
SOCK = os.environ.get("SECCHECK_SOCKET", "/run/seccheck/events.sock")
MAX_PACKET = 512 * 1024
DANGEROUS_COMMANDS = [
    "sh", "bash", "dash", "zsh",
    "curl", "wget", "nc", "ncat",
    "socat", "python", "python3",
    "perl", "php", "node", "telnetd", "sudo", "su",
    "ssh-keysign", "newgrp", "umount", "chfn", "passwd",
    "mount", "chsh", "gpasswd"
]

# Allowlist safe commands here
SAFE_ARGV = [
    # cronjob
    ['/bin/sh', '-c', 'cd / && run-parts --report /etc/cron.hourly'],
    ['/bin/sh', '-c', 'cd / && run-parts --report /etc/cron.daily'],
    ['/bin/sh', '-c', 'cd / && run-parts --report /etc/cron.weekly'],
    ['/bin/sh', '-c', 'cd / && run-parts --report /etc/cron.monthly'],
    ['run-parts', '--report', '/etc/cron.hourly'],
    ['run-parts', '--report', '/etc/cron.daily'],
    ['run-parts', '--report', '/etc/cron.weekly'],
    ['run-parts', '--report', '/etc/cron.monthly'],
]

# Tiny descriptors: protobuf runtime safely ignores fields we do not need
f = d.FileDescriptorProto(name="seccheck_min.proto", package="sc", syntax="proto3")
def msg(name):
    m = f.message_type.add(); m.name = name; return m

def field(m, number, name, typ, target=""):
    a = m.field.add(); a.name = name; a.number = number
    a.label = d.FieldDescriptorProto.LABEL_OPTIONAL; a.type = typ
    if target: a.type_name = target

def repeated_field(m, number, name, typ):
    a = m.field.add()
    a.name = name
    a.number = number
    a.label = d.FieldDescriptorProto.LABEL_REPEATED
    a.type = typ

S = d.FieldDescriptorProto.TYPE_STRING
I = d.FieldDescriptorProto.TYPE_INT32
B = d.FieldDescriptorProto.TYPE_BOOL
M = d.FieldDescriptorProto.TYPE_MESSAGE

m = msg("Handshake"); field(m, 1, "version", d.FieldDescriptorProto.TYPE_UINT32)
m = msg("Context"); field(m, 4, "pid", I); field(m, 6, "container_id", S)
field(m, 9, "process_name", S); field(m, 11, "is_exec_session", B)
m = msg("ExecInfo")
field(m, 1, "context", M, ".sc.Context")
field(m, 2, "binary_path", S)
repeated_field(m, 3, "argv", S)
m = msg("ExecCall")
field(m, 1, "context", M, ".sc.Context")
field(m, 6, "pathname", S)
repeated_field(m, 7, "argv", S)

pool = descriptor_pool.DescriptorPool(); pool.Add(f)
def cls(name):
    try:
        return message_factory.GetMessageClass(pool.FindMessageTypeByName("sc." + name))
    except:
        descriptor = pool.FindMessageTypeByName("sc." + name)

        if hasattr(message_factory, "GetMessageClass"):
            return message_factory.GetMessageClass(descriptor)

        return message_factory.MessageFactory(pool).GetPrototype(
            descriptor
        )

Handshake, ExecInfo, ExecCall = (cls(n) for n in ("Handshake", "ExecInfo", "ExecCall"))

last_alert = 0
alert_lock = threading.Lock()

def discord_alert(container, path, argv):
    global last_alert

    # only alert once in every 30s if there are multiples
    with alert_lock:
        now = time.monotonic()
        if now - last_alert < 30:
            return
        last_alert = now

    argv = repr(argv)[:256]
    def send():
        data = json.dumps({
            "username": "SecCheck",
            "content": (
                f"🚨 **gVisor Execution Alert**\n"
                f"**Host:** {socket.gethostname()}\n"
                f"**Container:** {container[:12]}\n"
                f"**Executable:** {path[:256]}\n"
                f"**Argv:** {argv}"
            ),
            "allowed_mentions": {"parse": []}
        }).encode()

        req = urllib.request.Request(
            WEBHOOK,
            data=data,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "SecCheckMonitor/1.0"
            }
        )

        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                r.read()
        except Exception as e:
            print(f"Discord alert failed: {e}", flush=True)

    threading.Thread(target=send, daemon=True).start()

def handle(c):
    with c:
        c.settimeout(10)
        try:
            raw, _, flags, _ = c.recvmsg(1024)
            if not raw or flags & socket.MSG_TRUNC:
                return
            h = Handshake(); h.ParseFromString(raw)
            if h.version != 1:
                print(f"unsupported SecCheck protocol: {h.version}", flush=True)
                return
            reply = Handshake(); reply.version = 1
            c.sendall(reply.SerializeToString())
            c.settimeout(None)
            while True:
                raw, _, flags, _ = c.recvmsg(MAX_PACKET)
                if not raw:
                    break
                if flags & socket.MSG_TRUNC or len(raw) < 8:
                    print("oversized/truncated event; dropping connection", flush=True)
                    break
                header_size, kind, dropped = struct.unpack_from("<HHI", raw)
                if header_size < 8 or header_size > len(raw):
                    break
                if dropped:
                    print(f"WARNING: gVisor reports {dropped} dropped events", flush=True)
                if kind not in (3, 11):
                    continue
                e = ExecInfo() if kind == 3 else ExecCall()
                e.ParseFromString(raw[header_size:])
                ctx = e.context
                path = (e.binary_path if kind == 3 else e.pathname)[:512]
                name = "EXEC" if kind == 3 else "EXEC_ATTEMPT"
                argv = [arg[:256] for arg in e.argv[:16]]
                truncated = len(e.argv) > 16 or any(len(arg) > 256 for arg in e.argv)

                print(
                    f"{name} container={ctx.container_id[:64]} "
                    f"pid={ctx.pid} "
                    f"process={ctx.process_name[:64]} "
                    f"docker_exec={ctx.is_exec_session} "
                    f"path={path!r} "
                    f"argv={argv!r}"
                    f"{' [truncated]' if truncated else ''}",
                    flush=True
                )

                # log everything by default...
                if argv in SAFE_ARGV:
                    continue

                # alert for dangerous commands
                if (
                    name == "EXEC_ATTEMPT"
                    and not ctx.is_exec_session
                    and os.path.basename(path) in DANGEROUS_COMMANDS
                ):
                    discord_alert(ctx.container_id, path, argv)
        except Exception as exc:
            print(f"receiver: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)


def main():
    os.makedirs(os.path.dirname(SOCK), mode=0o700, exist_ok=True)
    os.chmod(os.path.dirname(SOCK), 0o700)
    if os.path.lexists(SOCK):
        raise SystemExit(f"socket exists: {SOCK}; remove it only if no receiver is running")
    def stop(_signum, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, stop)
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as s:
        s.bind(SOCK)
        os.chmod(SOCK, 0o600)
        s.listen(16)
        print(f"Listening: {SOCK}", flush=True)
        try:
            while True:
                conn, _ = s.accept()
                threading.Thread(target=handle, args=(conn,), daemon=True).start()
        except KeyboardInterrupt:
            pass
        finally:
            os.unlink(SOCK)

if __name__ == "__main__":
    main(
