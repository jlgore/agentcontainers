#!/bin/sh
# ac-applevm dind entrypoint wrapper.
#
# Shadows the upstream docker:dind dockerd-entrypoint.sh (preserved as
# real-dockerd-entrypoint.sh). It hands off to the real entrypoint to run
# dockerd as the container's main process, but first kicks off a background
# task that — once dockerd is accepting connections — (1) loads the embedded
# agentcontainer-enforcer image into the in-VM Docker daemon and (2) starts the
# vsock<->docker.sock relay the host (ac-applevmd) dials.
#
# Why the enforcer load: the agentcontainers runtime starts the enforcer as a
# sidecar and EnsureImage checks the local store before pulling
# (internal/sidecar). Loading the image here makes that local check succeed, so
# the enforcer starts without a ghcr pull (offline / air-gapped, and pinned to
# the embedded digest).
#
# Why the vsock relay: dockerd listens only on its unix socket (no TCP on
# vmnet). The host reaches the Docker API over the hypervisor-mediated vsock
# channel; socat bridges the fixed vsock port to /var/run/docker.sock. It is
# started only AFTER `docker info` succeeds, so a successful host dialVsock
# means dockerd is genuinely ready (no premature-readiness race).
set -e

# Must match dockerdVsockPort in ac-applevmd (0x20000).
DOCKER_VSOCK_PORT=131072
ENFORCER_TAR=/opt/ac/enforcer.tar
ENFORCER_STATUS=/run/ac-enforcer-status

(
	# Wait for the daemon (up to ~60s) on its unix socket, then load the
	# enforcer image and start the relay.
	i=0
	while [ "$i" -lt 60 ]; do
		if docker info >/dev/null 2>&1; then
			if [ -f "$ENFORCER_TAR" ]; then
				if docker load -i "$ENFORCER_TAR" >/dev/null 2>&1; then
					echo "[ac-applevm] embedded enforcer image loaded" >&2
					echo loaded > "$ENFORCER_STATUS" 2>/dev/null || true
				else
					echo "[ac-applevm] enforcer image load failed (non-fatal)" >&2
					echo failed > "$ENFORCER_STATUS" 2>/dev/null || true
				fi
			else
				echo "[ac-applevm] no embedded enforcer image present" >&2
				echo missing > "$ENFORCER_STATUS" 2>/dev/null || true
			fi
			echo "[ac-applevm] starting vsock docker relay on port $DOCKER_VSOCK_PORT" >&2
			socat VSOCK-LISTEN:"$DOCKER_VSOCK_PORT",fork UNIX-CONNECT:/var/run/docker.sock &
			break
		fi
		i=$((i + 1))
		sleep 1
	done
) &

exec /usr/local/bin/real-dockerd-entrypoint.sh "$@"
