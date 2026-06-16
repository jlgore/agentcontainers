# syntax=docker/dockerfile:1
#
# The applevm microVM workload image with the agentcontainers enforcer embedded.
# It is plain docker:dind plus the enforcer image baked in as a tarball, loaded
# into the in-VM Docker daemon on startup so the enforcer sidecar runs without a
# ghcr pull. Built for linux/arm64 (Apple silicon microVMs). See README.md.
ARG DIND_BASE=docker:dind
FROM ${DIND_BASE}

# socat fronts dockerd's unix socket on a vsock port so the host (ac-applevmd)
# can reach the Docker API over the hypervisor-mediated vsock channel instead of
# TCP on vmnet. docker:dind is Alpine-based, so this is a single apk add.
RUN apk add --no-cache socat

# Preserve the upstream dind entrypoint and shadow it with our wrapper at the
# same path, so the agentcontainers runtime's invocation
# ("dockerd-entrypoint.sh dockerd -H ...") transparently loads the enforcer.
RUN cp /usr/local/bin/dockerd-entrypoint.sh /usr/local/bin/real-dockerd-entrypoint.sh
COPY dockerd-entrypoint.sh /usr/local/bin/dockerd-entrypoint.sh
RUN chmod 0755 /usr/local/bin/dockerd-entrypoint.sh /usr/local/bin/real-dockerd-entrypoint.sh

# The agentcontainer-enforcer image, `docker save`'d with its ghcr tag preserved
# (CI produces enforcer.tar). `docker load` restores that exact ref, which is
# what internal/sidecar.DefaultEnforcerImage looks up locally before pulling.
COPY enforcer.tar /opt/ac/enforcer.tar
