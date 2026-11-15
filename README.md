# gVisor seccheck listener in python3

Requires `python3` + `python3-protobuf` from Debian packages; runsc (gVisor) is required to run this application.

This example code will send notifications via Discord webhook for any dangerous execve/exec syscalls made from a gvisor-sandboxed container.

## Setup

Tested on Debian 13.

1. Move `seccheck/` folder to `/root/seccheck`

2. Run the following command to finish setting up
```sh
sudo apt-get install -y python3-protobuf
sudo cp seccheck.service /etc/systemd/system/seccheck.service
sudo runsc install \
  --runtime=runsc-seccheck -- \
  --pod-init-config=/root/seccheck/session.json
# adjust /etc/docker/daemon.json appropriately
sudo systemctl daemon-reload
sudo systemctl enable --now seccheck
sudo systemctl status seccheck
```

3. Verify
```sh
docker run -d --name sec-test --runtime=runsc-seccheck alpine:3.21 sleep 600
CID=$(docker inspect -f '{{.Id}}' sec-test)
sudo runsc --root /var/run/docker/runtime-runc/moby trace create --config /root/seccheck/session.json "$CID"
sudo runsc --root /var/run/docker/runtime-runc/moby trace list "$CID"
docker exec sec-test /bin/sh -c '/bin/true; echo ok'
sudo systemctl status seccheck.service
```

4. Clean up the verification

```sh
sudo runsc --root /var/run/docker/runtime-runc/moby trace delete --name Default "$CID"
docker rm -f sec-test
```

## Caveats

* No cloud exposure: the socket parent is root-only and the listener has no TCP port.
* Avoid sensitive `argv`, `envv`, `env` optional fields, and treat all incoming events as untrusted.
* This demo reads only a few event types, and does not offer full loss detection, persistence, or forensic completeness.
