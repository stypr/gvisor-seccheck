# gVisor SecCheck alerts

A small, dependency-light listener that turns selected
[gVisor runtime-monitoring](https://gvisor.dev/docs/user_guide/runtimemonitor/)
events into Discord alerts.

It listens on a root-only Unix socket, logs execution events to the systemd
journal, and alerts when a container workload attempts to run a command such as
`sh`, `curl`, `nc`, `python`, or `mount`. Docker `exec` sessions are logged but
do not trigger Discord alerts.

> [!IMPORTANT]
> This is a focused monitoring example, not a complete intrusion-detection or
> forensic system. Read [Security and limitations](#security-and-limitations)
> before relying on it.

## How it works

```text
gVisor container
    -> SecCheck remote sink
    -> /run/seccheck/events.sock
    -> receiver.py
       |-> systemd journal (all supported execution events)
       `-> Discord embed (selected execution attempts, rate-limited)
```

The receiver uses the official version 1 wire format and defines only the
protobuf fields it needs. Unknown fields are ignored by the protobuf runtime.

## Requirements

- Linux with systemd
- Docker with a working gVisor (`runsc`) installation
- Python 3
- Debian's `python3-protobuf` and `python3-dotenv` packages
- A Discord webhook URL

The included service and paths target Debian 13 and a root-owned installation
at `/root/seccheck`.

## Install

1. Install the Python dependency:

   ```sh
   sudo apt-get update
   sudo apt-get install -y python3-protobuf python3-dotenv
   ```

2. Install the listener files:

   ```sh
   sudo install -d -m 0700 /root/seccheck
   sudo install -m 0755 seccheck/receiver.py seccheck/reconnect.sh /root/seccheck/
   sudo install -m 0644 seccheck/session.json /root/seccheck/session.json
   sudo install -m 0600 seccheck/.env.example /root/seccheck/.env
   sudo install -m 0644 seccheck/seccheck.service /etc/systemd/system/seccheck.service
   ```

3. Open `/root/seccheck/.env` and replace the webhook placeholder:

   ```sh
   sudoedit /root/seccheck/.env
   ```

   The file contains all settings, including `DISCORD_WEBHOOK_URL`. It is mode
   `0600` and ignored by Git.

4. Install a dedicated gVisor runtime that loads the SecCheck session:

   ```sh
   sudo runsc install \
     --runtime=runsc-seccheck -- \
     --pod-init-config=/root/seccheck/session.json
   ```

   Confirm that Docker's `daemon.json` contains the new `runsc-seccheck`
   runtime, then restart Docker:

   ```sh
   sudo systemctl restart docker
   ```

   Restarting Docker can affect running containers, so schedule this step
   appropriately on a shared host.

5. Start the listener:

   ```sh
   sudo systemctl daemon-reload
   sudo systemctl enable --now seccheck.service
   sudo systemctl status seccheck.service
   ```

## Verify the setup

Start a temporary container using the dedicated runtime:

```sh
docker run -d --name seccheck-test \
  --runtime=runsc-seccheck alpine:3.21 sleep 600
container_id=$(docker inspect --format '{{.Id}}' seccheck-test)
```

Attach the trace session if it was not created automatically, then generate a
harmless shell event:

```sh
sudo runsc --root /var/run/docker/runtime-runc/moby trace create \
  --force --config /root/seccheck/session.json "$container_id"
sudo runsc --root /var/run/docker/runtime-runc/moby trace list "$container_id"
docker exec seccheck-test /bin/sh -c '/bin/true; echo ok'
sudo journalctl -u seccheck.service -n 50 --no-pager
```

The `docker exec` command should appear in the journal. It intentionally does
not create a Discord alert because interactive/admin exec sessions are excluded.
To test alert delivery, start a shell as the container's normal workload rather
than through `docker exec`:

```sh
docker run --rm --runtime=runsc-seccheck alpine:3.21 \
  /bin/sh -c 'echo "SecCheck alert test"'
```

Clean up the test container and trace session:

```sh
sudo runsc --root /var/run/docker/runtime-runc/moby trace delete \
  --name Default "$container_id"
docker rm -f seccheck-test
```

## Configuration

Structured alert policy remains near the top of `receiver.py`:

- `DANGEROUS_COMMANDS` controls executable basenames that can trigger alerts.
- `SAFE_ARGV` suppresses alerts for exact, known-safe argument vectors while
  retaining their journal entries.

All runtime settings live together in `/root/seccheck/.env`. `python-dotenv`
loads the same file when running the receiver directly, while systemd loads it
for the service and reconnect helper:

| Setting | Default | Purpose |
| --- | --- | --- |
| `DISCORD_WEBHOOK_URL` | required | Discord destination and authentication |
| `SECCHECK_SOCKET` | `/run/seccheck/events.sock` | Listener socket path |
| `SECCHECK_ALERT_COOLDOWN` | `30` | Global Discord cooldown in seconds |
| `SECCHECK_DISCORD_USERNAME` | `gVisor SecCheck` | Webhook display name |
| `RUNSC_ROOT` | `/var/run/docker/runtime-runc/moby` | gVisor state root |
| `SECCHECK_CONFIG` | `/root/seccheck/session.json` | Trace configuration |

Set `SECCHECK_ENV_FILE` before launching manually to load a different `.env`
path. Existing process environment variables take precedence over file values.

Useful operations:

```sh
sudo journalctl -u seccheck.service -f
sudo systemctl restart seccheck.service
sudo systemctl stop seccheck.service
```

## Security and limitations

- The socket directory is mode `0700`, the socket is mode `0600`, and no TCP
  listener is exposed.
- The `.env` file contains the webhook secret and is installed with mode `0600`.
  Do not commit or share it.
- Only HTTPS URLs on Discord's webhook endpoint are accepted.
- Event data is untrusted. Logged paths and arguments are length-limited, but
  they may still contain sensitive values; avoid enabling SecCheck fields such
  as environment variables unless you have a secure logging policy.
- Discord receives a bounded embed containing the executable path and truncated
  argument vector. Do not keep this if arguments may contain secrets.
- Alerts are best-effort and globally rate-limited. There is no queue,
  persistence, retry policy, or complete loss detection.
- Command matching is a basename heuristic, not an enforcement boundary. A
  renamed binary, symlink, or unlisted interpreter can evade an alert rule.
- Only execution-related event kinds used by this example are decoded. This is
  not a replacement for host monitoring, centralized audit logs, or incident
  response tooling.
