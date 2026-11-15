#!/bin/bash

ROOT="/var/run/docker/runtime-runc/moby"
CONFIG="/root/seccheck/session.json"

# Check for receiver
for i in {1..30}; do
    [ -S /run/seccheck/events.sock ] && break
    sleep 0.2
done

if [ ! -S /run/seccheck/events.sock ]; then
    echo "SecCheck receiver socket not found"
    exit 1
fi

docker ps -q | while read -r CID; do
    RUNTIME=$(docker inspect -f '{{.HostConfig.Runtime}}' "$CID")
    NAME=$(docker inspect -f '{{.Name}}' "$CID")

    # only run on gVisor
    case "$RUNTIME" in
        runsc|runsc-*) ;;
        *) continue ;;
    esac

    echo "[*] Reconnecting $NAME ($RUNTIME)"

    runsc --root "$ROOT" \
        trace create --force \
        --config "$CONFIG" "$CID" \
        || echo "[!] Failed: $NAME"
done
