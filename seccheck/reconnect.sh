#!/usr/bin/env bash

set -o nounset
set -o pipefail

readonly RUNSC_ROOT="${RUNSC_ROOT:-/var/run/docker/runtime-runc/moby}"
readonly SECCHECK_CONFIG="${SECCHECK_CONFIG:-/root/seccheck/session.json}"
readonly SECCHECK_SOCKET="${SECCHECK_SOCKET:-/run/seccheck/events.sock}"

# ExecStartPost can run before the receiver has finished creating its socket.
for _ in {1..30}; do
    [[ -S "$SECCHECK_SOCKET" ]] && break
    sleep 0.2
done

if [[ ! -S "$SECCHECK_SOCKET" ]]; then
    echo "SecCheck receiver socket not found: $SECCHECK_SOCKET" >&2
    exit 1
fi

container_ids=$(docker ps --quiet) || {
    echo "Unable to list running Docker containers" >&2
    exit 0
}

while IFS= read -r container_id; do
    [[ -n "$container_id" ]] || continue

    runtime=$(docker inspect --format '{{.HostConfig.Runtime}}' "$container_id") || {
        echo "[!] Unable to inspect container: $container_id" >&2
        continue
    }
    name=$(docker inspect --format '{{.Name}}' "$container_id") || {
        echo "[!] Unable to read container name: $container_id" >&2
        continue
    }
    name=${name#/}

    case "$runtime" in
        runsc | runsc-*) ;;
        *) continue ;;
    esac

    echo "[*] Reconnecting $name ($runtime)"
    runsc --root "$RUNSC_ROOT" \
        trace create --force \
        --config "$SECCHECK_CONFIG" "$container_id" \
        || echo "[!] Failed to reconnect: $name" >&2
done <<< "$container_ids"
