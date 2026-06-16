#!/bin/sh
# ac-applevm dind entrypoint wrapper.
#
# Shadows the upstream docker:dind dockerd-entrypoint.sh (preserved as
# real-dockerd-entrypoint.sh). It hands off to the real entrypoint to run
# dockerd as the container's main process, but first kicks off a background
# task that — once dockerd is accepting connections — loads the embedded
# agentcontainer-enforcer image into the in-VM Docker daemon.
#
# Why: the agentcontainers runtime starts the enforcer as a sidecar and
# EnsureImage checks the local store before pulling (internal/sidecar). Loading
# the image here makes that local check succeed, so the enforcer starts without
# a ghcr pull (offline / air-gapped, and pinned to the embedded digest).
set -e

ENFORCER_TAR=/opt/ac/enforcer.tar

if [ -f "$ENFORCER_TAR" ]; then
	(
		# Best-effort: wait for the daemon (up to ~60s) then load the image.
		# Uses the default unix socket, which dockerd also listens on.
		i=0
		while [ "$i" -lt 60 ]; do
			if docker info >/dev/null 2>&1; then
				if docker load -i "$ENFORCER_TAR" >/dev/null 2>&1; then
					echo "[ac-applevm] embedded enforcer image loaded" >&2
				else
					echo "[ac-applevm] enforcer image load failed (non-fatal)" >&2
				fi
				break
			fi
			i=$((i + 1))
			sleep 1
		done
	) &
fi

exec /usr/local/bin/real-dockerd-entrypoint.sh "$@"
