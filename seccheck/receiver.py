#!/usr/bin/env python3
"""Receive gVisor SecCheck events and send selected alerts to Discord.

This listener implements version 1 of gVisor's remote SecCheck wire protocol.
It intentionally defines only the protobuf fields used by the application;
protobuf safely ignores the remaining fields.
"""

from __future__ import annotations

import json
import os
import signal
import socket
import struct
import sys
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path

from google.protobuf import descriptor_pb2
from google.protobuf import descriptor_pool, message_factory


PROTOCOL_VERSION = 1
HANDSHAKE_SIZE = 1024
MAX_PACKET_SIZE = 512 * 1024
EVENT_HEADER = struct.Struct("<HHI")
# Values from gvisor.common.MessageType in SecCheck's common.proto.
SENTRY_EXEC_EVENT = 3
SYSCALL_EXECVE_EVENT = 11
ALERT_COOLDOWN_SECONDS = 30

SOCKET_PATH = Path(os.environ.get("SECCHECK_SOCKET", "/run/seccheck/events.sock"))
ENV_PATH = Path(os.environ.get("SECCHECK_ENV_FILE", "/root/seccheck/.env"))
WEBHOOK_URL_KEY = "DISCORD_WEBHOOK_URL"

# Add dangerous commands and relevant setuid or setgid commands here.
DANGEROUS_COMMANDS = {
    "bash",
    "chfn",
    "chsh",
    "curl",
    "dash",
    "gpasswd",
    "mount",
    "nc",
    "ncat",
    "newgrp",
    "node",
    "passwd",
    "perl",
    "php",
    "python",
    "python3",
    "sh",
    "socat",
    "ssh-keysign",
    "su",
    "sudo",
    "telnetd",
    "umount",
    "wget",
    "zsh",
}

# Exact argument vectors that should be logged without producing an alert.
SAFE_ARGV = [
    ["/bin/sh", "-c", "cd / && run-parts --report /etc/cron.hourly"],
    ["/bin/sh", "-c", "cd / && run-parts --report /etc/cron.daily"],
    ["/bin/sh", "-c", "cd / && run-parts --report /etc/cron.weekly"],
    ["/bin/sh", "-c", "cd / && run-parts --report /etc/cron.monthly"],
    ["run-parts", "--report", "/etc/cron.hourly"],
    ["run-parts", "--report", "/etc/cron.daily"],
    ["run-parts", "--report", "/etc/cron.weekly"],
    ["run-parts", "--report", "/etc/cron.monthly"],
]


def _add_message(file_descriptor, name):
    message = file_descriptor.message_type.add()
    message.name = name
    return message


def _add_field(message, number, name, field_type, *, repeated=False, target=""):
    field = message.field.add()
    field.name = name
    field.number = number
    field.label = (
        descriptor_pb2.FieldDescriptorProto.LABEL_REPEATED
        if repeated
        else descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    )
    field.type = field_type
    if target:
        field.type_name = target


def _message_classes():
    """Build minimal protobuf classes for the SecCheck messages we consume."""
    file_descriptor = descriptor_pb2.FileDescriptorProto(
        name="seccheck_min.proto",
        package="sc",
        syntax="proto3",
    )

    string = descriptor_pb2.FieldDescriptorProto.TYPE_STRING
    integer = descriptor_pb2.FieldDescriptorProto.TYPE_INT32
    boolean = descriptor_pb2.FieldDescriptorProto.TYPE_BOOL
    message_type = descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE

    handshake = _add_message(file_descriptor, "Handshake")
    _add_field(
        handshake,
        1,
        "version",
        descriptor_pb2.FieldDescriptorProto.TYPE_UINT32,
    )

    context = _add_message(file_descriptor, "ContextData")
    _add_field(context, 4, "thread_group_id", integer)
    _add_field(context, 6, "container_id", string)
    _add_field(context, 9, "process_name", string)
    _add_field(context, 11, "is_exec_session", boolean)

    exec_info = _add_message(file_descriptor, "ExecveInfo")
    _add_field(exec_info, 1, "context_data", message_type, target=".sc.ContextData")
    _add_field(exec_info, 2, "binary_path", string)
    _add_field(exec_info, 3, "argv", string, repeated=True)

    exec_call = _add_message(file_descriptor, "Execve")
    _add_field(exec_call, 1, "context_data", message_type, target=".sc.ContextData")
    _add_field(exec_call, 6, "pathname", string)
    _add_field(exec_call, 7, "argv", string, repeated=True)

    pool = descriptor_pool.DescriptorPool()
    pool.Add(file_descriptor)

    def message_class(name):
        descriptor = pool.FindMessageTypeByName(f"sc.{name}")
        get_message_class = getattr(message_factory, "GetMessageClass", None)
        if get_message_class is not None:
            return get_message_class(descriptor)
        return message_factory.MessageFactory(pool).GetPrototype(descriptor)

    return tuple(
        message_class(name) for name in ("Handshake", "ExecveInfo", "Execve")
    )


Handshake, ExecveInfo, Execve = _message_classes()


def _is_discord_webhook_url(webhook_url: str) -> bool:
    try:
        parsed_url = urllib.parse.urlsplit(webhook_url)
        port = parsed_url.port
    except ValueError:
        return False

    path_parts = parsed_url.path.split("/")
    return (
        parsed_url.scheme == "https"
        and parsed_url.hostname in {"discord.com", "discordapp.com"}
        and parsed_url.username is None
        and parsed_url.password is None
        and port in (None, 443)
        and len(path_parts) == 5
        and path_parts[1:3] == ["api", "webhooks"]
        and all(path_parts[3:])
        and not parsed_url.fragment
    )


def _read_webhook_url() -> str:
    try:
        env_text = ENV_PATH.read_text(encoding="utf-8")
        file_mode = ENV_PATH.stat().st_mode & 0o777
    except OSError as exc:
        message = f"cannot read environment file {ENV_PATH}: {exc}"
        raise SystemExit(message) from exc

    if file_mode & 0o077:
        raise SystemExit(
            f"environment file must not be group/world accessible: {ENV_PATH}"
        )

    webhook_url = None
    for raw_line in env_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        key, separator, value = line.partition("=")
        if separator and key.strip() == WEBHOOK_URL_KEY:
            if webhook_url is not None:
                raise SystemExit(f"duplicate {WEBHOOK_URL_KEY} in {ENV_PATH}")
            webhook_url = value.strip()

    if webhook_url is None:
        raise SystemExit(f"missing {WEBHOOK_URL_KEY} in {ENV_PATH}")
    if (
        len(webhook_url) >= 2
        and webhook_url[0] == webhook_url[-1]
        and webhook_url[0] in ("'", '"')
    ):
        webhook_url = webhook_url[1:-1]

    if not _is_discord_webhook_url(webhook_url):
        raise SystemExit(f"invalid Discord webhook URL in {ENV_PATH}")
    return webhook_url


class DiscordAlerts:
    """Send rate-limited Discord alerts without blocking event processing."""

    def __init__(self, webhook_url: str):
        self._webhook_url = webhook_url
        self._last_alert = 0.0
        self._lock = threading.Lock()

    def notify(self, container: str, path: str, argv: list[str]) -> None:
        with self._lock:
            now = time.monotonic()
            if now - self._last_alert < ALERT_COOLDOWN_SECONDS:
                return
            self._last_alert = now

        thread = threading.Thread(
            target=self._send,
            args=(container, path, argv),
            name="discord-alert",
            daemon=True,
        )
        thread.start()

    def _send(self, container: str, path: str, argv: list[str]) -> None:
        path_text = repr(path)[:256]
        argv_text = repr(argv)[:256]
        payload = json.dumps(
            {
                "username": "SecCheck",
                "content": (
                    "🚨 **gVisor Execution Alert**\n"
                    f"**Host:** {socket.gethostname()}\n"
                    f"**Container:** {container[:12]}\n"
                    f"**Executable:** {path_text}\n"
                    f"**Argv:** {argv_text}"
                ),
                "allowed_mentions": {"parse": []},
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            self._webhook_url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "SecCheckMonitor/1.0",
            },
        )

        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                response.read(1024)
        except Exception as exc:  # Keep monitoring even if Discord is unavailable.
            print(f"Discord alert failed: {exc}", file=sys.stderr, flush=True)


def _should_alert(event_kind: int, is_exec_session: bool, path: str) -> bool:
    return (
        event_kind == SYSCALL_EXECVE_EVENT
        and not is_exec_session
        and os.path.basename(path) in DANGEROUS_COMMANDS
    )


def _handle_event(raw: bytes, alerts: DiscordAlerts) -> bool:
    """Process one event packet; return False when the connection is invalid."""
    if len(raw) < EVENT_HEADER.size:
        print("short event header; dropping connection", file=sys.stderr, flush=True)
        return False

    header_size, event_kind, dropped = EVENT_HEADER.unpack_from(raw)
    if header_size < EVENT_HEADER.size or header_size > len(raw):
        print("invalid event header; dropping connection", file=sys.stderr, flush=True)
        return False

    if dropped:
        print(f"WARNING: gVisor reports {dropped} dropped events", flush=True)
    if event_kind not in (SENTRY_EXEC_EVENT, SYSCALL_EXECVE_EVENT):
        return True

    event = ExecveInfo() if event_kind == SENTRY_EXEC_EVENT else Execve()
    event.ParseFromString(raw[header_size:])

    context = event.context_data
    path = (
        event.binary_path if event_kind == SENTRY_EXEC_EVENT else event.pathname
    )[:512]
    event_name = "EXEC" if event_kind == SENTRY_EXEC_EVENT else "EXEC_ATTEMPT"
    argv = [argument[:256] for argument in event.argv[:16]]
    was_truncated = len(event.argv) > 16 or any(
        len(argument) > 256 for argument in event.argv
    )

    print(
        f"{event_name} container={context.container_id[:64]} "
        f"pid={context.thread_group_id} "
        f"process={context.process_name[:64]} "
        f"docker_exec={context.is_exec_session} "
        f"path={path!r} "
        f"argv={argv!r}"
        f"{' [truncated]' if was_truncated else ''}",
        flush=True,
    )

    if argv in SAFE_ARGV:
        return True
    if _should_alert(event_kind, context.is_exec_session, path):
        alerts.notify(context.container_id, path, argv)
    return True


def handle_connection(connection: socket.socket, alerts: DiscordAlerts) -> None:
    with connection:
        try:
            connection.settimeout(10)
            raw, _, flags, _ = connection.recvmsg(HANDSHAKE_SIZE)
            if not raw or flags & socket.MSG_TRUNC:
                return

            handshake = Handshake()
            handshake.ParseFromString(raw)
            if handshake.version < PROTOCOL_VERSION:
                print(
                    f"unsupported SecCheck protocol: {handshake.version}",
                    file=sys.stderr,
                    flush=True,
                )
                return

            reply = Handshake()
            reply.version = PROTOCOL_VERSION
            connection.sendall(reply.SerializeToString())
            connection.settimeout(None)

            while True:
                raw, _, flags, _ = connection.recvmsg(MAX_PACKET_SIZE)
                if not raw:
                    return
                if flags & socket.MSG_TRUNC:
                    print(
                        "oversized event; dropping connection",
                        file=sys.stderr,
                        flush=True,
                    )
                    return
                if not _handle_event(raw, alerts):
                    return
        except Exception as exc:
            print(
                f"receiver: {type(exc).__name__}: {exc}",
                file=sys.stderr,
                flush=True,
            )


def _prepare_socket_directory() -> None:
    SOCKET_PATH.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    SOCKET_PATH.parent.chmod(0o700)
    if os.path.lexists(SOCKET_PATH):
        raise SystemExit(
            f"socket exists: {SOCKET_PATH}; remove it only if no receiver is running"
        )


def main() -> int:
    alerts = DiscordAlerts(_read_webhook_url())
    _prepare_socket_directory()

    def stop(_signum, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, stop)

    socket_created = False
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as server:
        try:
            server.bind(str(SOCKET_PATH))
            socket_created = True
            SOCKET_PATH.chmod(0o600)
            server.listen(16)
            print(f"Listening: {SOCKET_PATH}", flush=True)

            while True:
                connection, _ = server.accept()
                thread = threading.Thread(
                    target=handle_connection,
                    args=(connection, alerts),
                    name="seccheck-connection",
                    daemon=True,
                )
                thread.start()
        except KeyboardInterrupt:
            print("Stopping SecCheck receiver", flush=True)
        finally:
            if socket_created:
                SOCKET_PATH.unlink(missing_ok=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
