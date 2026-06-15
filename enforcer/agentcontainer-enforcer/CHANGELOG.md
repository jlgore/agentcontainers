# Changelog

## [0.1.6](https://github.com/jlgore/agentcontainers/compare/ac-enforcer-v0.1.5...ac-enforcer-v0.1.6) (2026-06-15)


### Bug Fixes

* **enforcer:** make exec-allowlist enforcement opt-in per cgroup ([#11](https://github.com/jlgore/agentcontainers/issues/11)) ([be49f53](https://github.com/jlgore/agentcontainers/commit/be49f533a5e44dc2db8a3a06476cc5157b1f6d7a))

## [0.1.5](https://github.com/jlgore/agentcontainers/compare/ac-enforcer-v0.1.4...ac-enforcer-v0.1.5) (2026-06-15)


### Bug Fixes

* **enforcer:** aggregate get_stats for empty container_id ([#9](https://github.com/jlgore/agentcontainers/issues/9)) ([55629e1](https://github.com/jlgore/agentcontainers/commit/55629e1f2a8521f9b65cb5d8ba8661797acba07b))

## [0.1.4](https://github.com/jlgore/agentcontainers/compare/ac-enforcer-v0.1.3...ac-enforcer-v0.1.4) (2026-06-15)


### Features

* add kernel-primary Docker Engine containment posture ([3df200e](https://github.com/jlgore/agentcontainers/commit/3df200e8ba93a2b01fe6ba18e9134b83176b18fe))
* kernel-primary Docker Engine containment posture ([1c37957](https://github.com/jlgore/agentcontainers/commit/1c3795761996c6f3d4901257e1e4df4cc457f7f4))

## [0.1.3](https://github.com/jlgore/agentcontainers/compare/ac-enforcer-v0.1.2...ac-enforcer-v0.1.3) (2026-06-15)


### Features

* **sidecar:** stable host-generated enforcer mTLS creds ([740024e](https://github.com/jlgore/agentcontainers/commit/740024e287b3f1c8a856a25959653940930542bf))


### Bug Fixes

* **enforcer:** document host-pushed --tls-* as the production mTLS path ([fb1e812](https://github.com/jlgore/agentcontainers/commit/fb1e81217086b4726fcba5625fbef823af18ed5b))

## [0.1.2](https://github.com/jlgore/agentcontainers/compare/ac-enforcer-v0.1.1...ac-enforcer-v0.1.2) (2026-06-14)


### Bug Fixes

* **enforcer:** default omitted egress protocol to tcp ([e7107b0](https://github.com/jlgore/agentcontainers/commit/e7107b08229e542bd54a380a379724e2b931aa61))

## [0.1.1](https://github.com/jlgore/agentcontainers/compare/ac-enforcer-v0.1.0...ac-enforcer-v0.1.1) (2026-06-14)


### Features

* **enforcer:** atomic, fail-closed secret bootstrap ([bff01a1](https://github.com/jlgore/agentcontainers/commit/bff01a1f55f248405dd470606c091201932dd863))
* **enforcer:** attach BPF programs; register MCP backends; DNS observation ([97bdb84](https://github.com/jlgore/agentcontainers/commit/97bdb8448892a4ed76677845d66d44d502d79f67))
* **enforcer:** enforce process execution allowlist (default-deny) ([9b23c2d](https://github.com/jlgore/agentcontainers/commit/9b23c2d3f36d30a7d087b5d1d1430349c624b39c))
* **enforcer:** kernel-enforced per-tool secret restrictions ([f07e0b4](https://github.com/jlgore/agentcontainers/commit/f07e0b4793fc3183b679c326e146cd8c19ca7068))
* **enforcer:** Phase 3 — per-cgroup BPF map rekeying + tool-call correlation ([915ce18](https://github.com/jlgore/agentcontainers/commit/915ce183a84e8edb23634afde739d24235f1064b))


### Bug Fixes

* **ebpf:** gate the DNS ingress hook by ENFORCED_CGROUPS ([310720c](https://github.com/jlgore/agentcontainers/commit/310720cac20164dab45f86934ad0dc9ce38b314c))
* **enforcer:** bound and prune tool-call correlation windows ([4fe3f89](https://github.com/jlgore/agentcontainers/commit/4fe3f899057b33f4471a8f732091d3792d1b5714))
* **enforcer:** cgroup hooks never attached — AllowMultiple is EINVAL on bpf_link_create ([1958945](https://github.com/jlgore/agentcontainers/commit/195894581418e4d915d3191204d3b42105fa50f6))
* **enforcer:** deliver in-band gap marker when the event bus drops events ([40e2be4](https://github.com/jlgore/agentcontainers/commit/40e2be4c2d04f6582e133d9bba2b70893900f4b8))
* **enforcer:** drain DNS_EVENTS — DNS observation was dead end-to-end ([6d2882a](https://github.com/jlgore/agentcontainers/commit/6d2882a114acf7d29c2a48ee8b0b42b876b46c20))
* **enforcer:** get ac_dns_ingress under the verifier (non-elidable masks, offset normalization) ([9a261db](https://github.com/jlgore/agentcontainers/commit/9a261db27e02ccf0477f2ca7a615a4d61cb0d952))
* **enforcer:** make DNS observation degrade gracefully; rework parser for the verifier ([3b4518e](https://github.com/jlgore/agentcontainers/commit/3b4518e7d60af205634fc25e1d25fa1558089ad2))
* **enforcer:** make FsInodeKey lookups actually match — dev_t decode + container-namespace path resolution ([9b86c5b](https://github.com/jlgore/agentcontainers/commit/9b86c5ba19ea249c6ccf32d2b263b7bbdbfe54c8))
* **enforcer:** own injected secrets by the agent's uid, not root ([8540db6](https://github.com/jlgore/agentcontainers/commit/8540db6dfa4a36a6606f6426768ceb20c9981ea5))
* **enforcer:** own ring buffers in the reader (was UAF); move DNS identification to userspace ([0db833c](https://github.com/jlgore/agentcontainers/commit/0db833c85ff32c2a4571484fe6a156dfdd6e5e94))
* **enforcer:** park drained events briefly to close the prepare-side correlation race ([38eb27c](https://github.com/jlgore/agentcontainers/commit/38eb27c1c29b6a3ea4a9722e90fa8ae321babe8d))
* **enforcer:** populate BLOCKED_CIDRS and ALLOWED_V6 — always-deny was dead code ([e2d65d0](https://github.com/jlgore/agentcontainers/commit/e2d65d0c6eef78a6203925379af75b5c84dea6e4))
* **enforcer:** re-applying network policy replaces the IP set instead of accumulating ([7d3fa89](https://github.com/jlgore/agentcontainers/commit/7d3fa894a7932dee722396a25c44022e4eae3fec))
* **enforcer:** report partial network-policy application to the proxy ([8be9ade](https://github.com/jlgore/agentcontainers/commit/8be9ade4e06bc7fad5f830295c5208857ce03380))
* **sec:** address spec-review findings on the 5 hardening PRs ([0af1114](https://github.com/jlgore/agentcontainers/commit/0af1114dc6b1f934cc03dd52eaadac5432989898))
