# Changelog

## [0.1.7](https://github.com/jlgore/agentcontainers/compare/v0.1.6...v0.1.7) (2026-06-15)


### Bug Fixes

* **enforcer:** aggregate get_stats for empty container_id ([#9](https://github.com/jlgore/agentcontainers/issues/9)) ([55629e1](https://github.com/jlgore/agentcontainers/commit/55629e1f2a8521f9b65cb5d8ba8661797acba07b))

## [0.1.6](https://github.com/jlgore/agentcontainers/compare/v0.1.5...v0.1.6) (2026-06-15)


### Bug Fixes

* **bootstrap:** verify CLI release under its real filename ([0b5602f](https://github.com/jlgore/agentcontainers/commit/0b5602f0cf32e4c7dbfcade54c2981b783da59d8))
* **cli:** discover enforcer mTLS creds for mcp start / status / diagnose ([e763ea5](https://github.com/jlgore/agentcontainers/commit/e763ea5ec16eab9556dab79edb0b7b77df11b458))

## [0.1.5](https://github.com/jlgore/agentcontainers/compare/v0.1.4...v0.1.5) (2026-06-15)


### Features

* add kernel-primary Docker Engine containment posture ([3df200e](https://github.com/jlgore/agentcontainers/commit/3df200e8ba93a2b01fe6ba18e9134b83176b18fe))
* kernel-primary Docker Engine containment posture ([1c37957](https://github.com/jlgore/agentcontainers/commit/1c3795761996c6f3d4901257e1e4df4cc457f7f4))

## [0.1.4](https://github.com/jlgore/agentcontainers/compare/v0.1.3...v0.1.4) (2026-06-15)


### Features

* **sidecar:** generate enforcer mTLS creds host-side with a stable directory ([7f10be4](https://github.com/jlgore/agentcontainers/commit/7f10be474e5cafbe4b6cda1377546081e1620ac7))
* **sidecar:** stable host-generated enforcer mTLS creds ([740024e](https://github.com/jlgore/agentcontainers/commit/740024e287b3f1c8a856a25959653940930542bf))


### Bug Fixes

* **enforcer:** document host-pushed --tls-* as the production mTLS path ([fb1e812](https://github.com/jlgore/agentcontainers/commit/fb1e81217086b4726fcba5625fbef823af18ed5b))
* **forensic-e2e:** make the proxy-path investigation segment actually run ([35609b5](https://github.com/jlgore/agentcontainers/commit/35609b5aa244fbbda1b83f6c11b5399b5e8ba8a4))

## [0.1.3](https://github.com/jlgore/agentcontainers/compare/v0.1.2...v0.1.3) (2026-06-14)


### Features

* **enforcer:** atomic, fail-closed secret bootstrap ([bff01a1](https://github.com/jlgore/agentcontainers/commit/bff01a1f55f248405dd470606c091201932dd863))
* **enforcer:** attach BPF programs; register MCP backends; DNS observation ([97bdb84](https://github.com/jlgore/agentcontainers/commit/97bdb8448892a4ed76677845d66d44d502d79f67))
* **enforcer:** enforce process execution allowlist (default-deny) ([9b23c2d](https://github.com/jlgore/agentcontainers/commit/9b23c2d3f36d30a7d087b5d1d1430349c624b39c))
* **enforcer:** kernel-enforced per-tool secret restrictions ([f07e0b4](https://github.com/jlgore/agentcontainers/commit/f07e0b4793fc3183b679c326e146cd8c19ca7068))
* **enforcer:** Phase 3 — per-cgroup BPF map rekeying + tool-call correlation ([915ce18](https://github.com/jlgore/agentcontainers/commit/915ce183a84e8edb23634afde739d24235f1064b))
* **enforcer:** secure control plane with loopback mTLS ([aee17e5](https://github.com/jlgore/agentcontainers/commit/aee17e563419acb4758b905baf2b9d7e4f121c0c))
* **examples:** claude-agent — Claude Code under zero-trust enforcement ([09c57fa](https://github.com/jlgore/agentcontainers/commit/09c57facfa07dbd388a17ea950173f190decd862))
* **examples:** claude-agent OAuth + API-key auth variants ([51dab2f](https://github.com/jlgore/agentcontainers/commit/51dab2fe472e32be4300caf9b986e6ceb845b497))
* **examples:** host sift demo over kernel-enforced container+http ([47079e0](https://github.com/jlgore/agentcontainers/commit/47079e08bd31742b4d6cb44238c393b6b3cfe822))
* **examples:** SIFT forensic platform as an enforced MCP tool ([dc8fad2](https://github.com/jlgore/agentcontainers/commit/dc8fad2123a9923b7682df18930246739ab96c43))
* **examples:** sift-platform demo lifecycle + bootstrap --with-sift-demo ([9a82e6d](https://github.com/jlgore/agentcontainers/commit/9a82e6d35242ca309c58acd97d5ec32daa103829))
* **exec:** interactive (-it) mode for human-driven agent sessions ([202cfcd](https://github.com/jlgore/agentcontainers/commit/202cfcd61673f81d85621ff8829de0206dca1787))
* **guard:** gate file-mutating tools, not just Bash ([4d0dd6e](https://github.com/jlgore/agentcontainers/commit/4d0dd6e5cb043f1a083d594e4f2d8b2f5b765352))
* **guard:** gate the agent's own tools via PreToolUse hook -&gt; OPA + HITL ([d5dbf66](https://github.com/jlgore/agentcontainers/commit/d5dbf66283956153e90f802d6891b12d646b7b9f))
* **guard:** inline approval mode + approval monitor TUI ([fda26dc](https://github.com/jlgore/agentcontainers/commit/fda26dc9d4d764f899ad847a8bf175356af32621))
* **guard:** normalize command wrappers before policy evaluation ([2613756](https://github.com/jlgore/agentcontainers/commit/2613756adda5fc0d2ad18be1173f11b7275f7934))
* **mcpproxy:** Phase 1 — MCP reverse proxy with audited tool-call passthrough ([fe7c9ca](https://github.com/jlgore/agentcontainers/commit/fe7c9ca370cf7bdb0ac58dec6173b2ecd78f89fe))
* **mcpproxy:** Phase 2 — in-process OPA policy evaluation on tools/call ([1acbc68](https://github.com/jlgore/agentcontainers/commit/1acbc6833502866cbaca2a7f3c9068e4af3b3efc))
* **mcpproxy:** Phase 4 — human-in-the-loop approval ([7996f9e](https://github.com/jlgore/agentcontainers/commit/7996f9ed1cbb679b11c3b48fcb2ae3e2b24798a9))
* **mcpproxy:** support container backends over HTTP transport ([1209c46](https://github.com/jlgore/agentcontainers/commit/1209c46dee7fbeb2f3c1e1a38731d5bf98ebd86e))
* **scripts:** add bootstrap.sh for one-shot workstation setup ([31a862d](https://github.com/jlgore/agentcontainers/commit/31a862dc4e2e960f01c0592e7acee90af4dfef1d))


### Bug Fixes

* **ci:** fix SLSA provenance hash generation for goreleaser v2 ([4448458](https://github.com/jlgore/agentcontainers/commit/4448458d12adabcbffcb57e58c1860d3ad078330))
* **ci:** publish CLI release artifacts with plain vX.Y.Z tags ([8bbf2ed](https://github.com/jlgore/agentcontainers/commit/8bbf2edcb7a558e5a7c838bf1bf25c250dcab644))
* **ci:** repair release workflow config ([58c26b2](https://github.com/jlgore/agentcontainers/commit/58c26b24a16d9fa635887f4863268f18d7cad7fc))
* **ci:** set goreleaser monorepo tag_prefix for ac- component tags ([f9c4cf1](https://github.com/jlgore/agentcontainers/commit/f9c4cf16d615237ab8f12acaf27607e1fd231973))
* **cli:** probe enforcer health eagerly at mcp start ([159d95b](https://github.com/jlgore/agentcontainers/commit/159d95b9225b86fed7a640cf22f2393ac54245ab))
* **ebpf:** gate the DNS ingress hook by ENFORCED_CGROUPS ([310720c](https://github.com/jlgore/agentcontainers/commit/310720cac20164dab45f86934ad0dc9ce38b314c))
* **enforcer:** bound and prune tool-call correlation windows ([4fe3f89](https://github.com/jlgore/agentcontainers/commit/4fe3f899057b33f4471a8f732091d3792d1b5714))
* **enforcer:** cgroup hooks never attached — AllowMultiple is EINVAL on bpf_link_create ([1958945](https://github.com/jlgore/agentcontainers/commit/195894581418e4d915d3191204d3b42105fa50f6))
* **enforcer:** default omitted egress protocol to tcp ([e7107b0](https://github.com/jlgore/agentcontainers/commit/e7107b08229e542bd54a380a379724e2b931aa61))
* **enforcer:** deliver in-band gap marker when the event bus drops events ([40e2be4](https://github.com/jlgore/agentcontainers/commit/40e2be4c2d04f6582e133d9bba2b70893900f4b8))
* **enforcer:** drain DNS_EVENTS — DNS observation was dead end-to-end ([6d2882a](https://github.com/jlgore/agentcontainers/commit/6d2882a114acf7d29c2a48ee8b0b42b876b46c20))
* **enforcer:** get ac_dns_ingress under the verifier (non-elidable masks, offset normalization) ([9a261db](https://github.com/jlgore/agentcontainers/commit/9a261db27e02ccf0477f2ca7a615a4d61cb0d952))
* **enforcer:** grant the sidecar CAP_SYS_PTRACE so secret injection works ([ac99c64](https://github.com/jlgore/agentcontainers/commit/ac99c64df9bffbe80563fd8d6cf553cfa580c3e8))
* **enforcer:** make DNS observation degrade gracefully; rework parser for the verifier ([3b4518e](https://github.com/jlgore/agentcontainers/commit/3b4518e7d60af205634fc25e1d25fa1558089ad2))
* **enforcer:** make FsInodeKey lookups actually match — dev_t decode + container-namespace path resolution ([9b86c5b](https://github.com/jlgore/agentcontainers/commit/9b86c5ba19ea249c6ccf32d2b263b7bbdbfe54c8))
* **enforcer:** own injected secrets by the agent's uid, not root ([8540db6](https://github.com/jlgore/agentcontainers/commit/8540db6dfa4a36a6606f6426768ceb20c9981ea5))
* **enforcer:** own ring buffers in the reader (was UAF); move DNS identification to userspace ([0db833c](https://github.com/jlgore/agentcontainers/commit/0db833c85ff32c2a4571484fe6a156dfdd6e5e94))
* **enforcer:** park drained events briefly to close the prepare-side correlation race ([38eb27c](https://github.com/jlgore/agentcontainers/commit/38eb27c1c29b6a3ea4a9722e90fa8ae321babe8d))
* **enforcer:** populate BLOCKED_CIDRS and ALLOWED_V6 — always-deny was dead code ([e2d65d0](https://github.com/jlgore/agentcontainers/commit/e2d65d0c6eef78a6203925379af75b5c84dea6e4))
* **enforcer:** re-applying network policy replaces the IP set instead of accumulating ([7d3fa89](https://github.com/jlgore/agentcontainers/commit/7d3fa894a7932dee722396a25c44022e4eae3fec))
* **enforcer:** report partial network-policy application to the proxy ([8be9ade](https://github.com/jlgore/agentcontainers/commit/8be9ade4e06bc7fad5f830295c5208857ce03380))
* harden MCP backend startup and continue audit chain across restarts ([2ab65f8](https://github.com/jlgore/agentcontainers/commit/2ab65f843a13c936428dba21118e2a82c327164a))
* **mcpproxy:** clean up phase 1 gaps ([9a0e00f](https://github.com/jlgore/agentcontainers/commit/9a0e00f601b0143e6f60b87552fe6c992a2f3728))
* **mcpproxy:** enforce policy.filesystem at the proxy; review fixes ([d1003f6](https://github.com/jlgore/agentcontainers/commit/d1003f612abcff04f3363f3ab9e8e929335577dc))
* **mcpproxy:** freeze stdio backend on start to close the unenforced window ([fde4b97](https://github.com/jlgore/agentcontainers/commit/fde4b976fd0ec17eb12001fc64059631ef81e859))
* **mcpproxy:** reconnect the enforcer audit stream; record gaps in the chain ([17434a1](https://github.com/jlgore/agentcontainers/commit/17434a185e1621ddff5e02acbd9caf5db80a61e5))
* **mcpproxy:** roll back enforcer registration on partial failure ([961fbfc](https://github.com/jlgore/agentcontainers/commit/961fbfceb80b6ab84d266efba4e91c43ae36c844))
* **mcpproxy:** surface proxy-only posture of filesystem allowlists ([f607f4e](https://github.com/jlgore/agentcontainers/commit/f607f4e6e5252f38844ff4a38a5c87abc6c49d66))
* **oci:** resolve multi-arch image indexes in policy manifest fetch ([5e8aa87](https://github.com/jlgore/agentcontainers/commit/5e8aa87ef9456ba54c02810ab462ad7f829406cf))
* replace remaining ac-enforcer and ac CLI references in Go source ([aaf7667](https://github.com/jlgore/agentcontainers/commit/aaf76670e9d128f7ef558312abbe3163997e851e))
* **run:** attach egress-enabled agents to a user-defined bridge for DNS ([fd83c2f](https://github.com/jlgore/agentcontainers/commit/fd83c2f7f8d3bbe81e327a9cb716b066fdd319fd))
* **sec:** address spec-review findings on the 5 hardening PRs ([0af1114](https://github.com/jlgore/agentcontainers/commit/0af1114dc6b1f934cc03dd52eaadac5432989898))
* **test:** eliminate race in enforcer liveness test ([9c3bee7](https://github.com/jlgore/agentcontainers/commit/9c3bee729b9d5c8e9f734d4fd679047ecc93e639))


### Reverts

* **ci:** drop invalid goreleaser monorepo block (Pro-only feature) ([7ffdb3c](https://github.com/jlgore/agentcontainers/commit/7ffdb3c2bee380ed30f38d78885680dda24b5764))

## [0.1.2](https://github.com/jlgore/agentcontainers/compare/ac-v0.1.1...ac-v0.1.2) (2026-06-14)


### Bug Fixes

* **ci:** set goreleaser monorepo tag_prefix for ac- component tags ([f9c4cf1](https://github.com/jlgore/agentcontainers/commit/f9c4cf16d615237ab8f12acaf27607e1fd231973))

## [0.1.1](https://github.com/jlgore/agentcontainers/compare/ac-v0.1.0...ac-v0.1.1) (2026-06-14)


### Features

* **enforcer:** atomic, fail-closed secret bootstrap ([bff01a1](https://github.com/jlgore/agentcontainers/commit/bff01a1f55f248405dd470606c091201932dd863))
* **enforcer:** attach BPF programs; register MCP backends; DNS observation ([97bdb84](https://github.com/jlgore/agentcontainers/commit/97bdb8448892a4ed76677845d66d44d502d79f67))
* **enforcer:** enforce process execution allowlist (default-deny) ([9b23c2d](https://github.com/jlgore/agentcontainers/commit/9b23c2d3f36d30a7d087b5d1d1430349c624b39c))
* **enforcer:** kernel-enforced per-tool secret restrictions ([f07e0b4](https://github.com/jlgore/agentcontainers/commit/f07e0b4793fc3183b679c326e146cd8c19ca7068))
* **enforcer:** Phase 3 — per-cgroup BPF map rekeying + tool-call correlation ([915ce18](https://github.com/jlgore/agentcontainers/commit/915ce183a84e8edb23634afde739d24235f1064b))
* **enforcer:** secure control plane with loopback mTLS ([aee17e5](https://github.com/jlgore/agentcontainers/commit/aee17e563419acb4758b905baf2b9d7e4f121c0c))
* **examples:** claude-agent — Claude Code under zero-trust enforcement ([09c57fa](https://github.com/jlgore/agentcontainers/commit/09c57facfa07dbd388a17ea950173f190decd862))
* **examples:** claude-agent OAuth + API-key auth variants ([51dab2f](https://github.com/jlgore/agentcontainers/commit/51dab2fe472e32be4300caf9b986e6ceb845b497))
* **examples:** host sift demo over kernel-enforced container+http ([47079e0](https://github.com/jlgore/agentcontainers/commit/47079e08bd31742b4d6cb44238c393b6b3cfe822))
* **examples:** SIFT forensic platform as an enforced MCP tool ([dc8fad2](https://github.com/jlgore/agentcontainers/commit/dc8fad2123a9923b7682df18930246739ab96c43))
* **examples:** sift-platform demo lifecycle + bootstrap --with-sift-demo ([9a82e6d](https://github.com/jlgore/agentcontainers/commit/9a82e6d35242ca309c58acd97d5ec32daa103829))
* **exec:** interactive (-it) mode for human-driven agent sessions ([202cfcd](https://github.com/jlgore/agentcontainers/commit/202cfcd61673f81d85621ff8829de0206dca1787))
* **guard:** gate file-mutating tools, not just Bash ([4d0dd6e](https://github.com/jlgore/agentcontainers/commit/4d0dd6e5cb043f1a083d594e4f2d8b2f5b765352))
* **guard:** gate the agent's own tools via PreToolUse hook -&gt; OPA + HITL ([d5dbf66](https://github.com/jlgore/agentcontainers/commit/d5dbf66283956153e90f802d6891b12d646b7b9f))
* **guard:** inline approval mode + approval monitor TUI ([fda26dc](https://github.com/jlgore/agentcontainers/commit/fda26dc9d4d764f899ad847a8bf175356af32621))
* **guard:** normalize command wrappers before policy evaluation ([2613756](https://github.com/jlgore/agentcontainers/commit/2613756adda5fc0d2ad18be1173f11b7275f7934))
* **mcpproxy:** Phase 1 — MCP reverse proxy with audited tool-call passthrough ([fe7c9ca](https://github.com/jlgore/agentcontainers/commit/fe7c9ca370cf7bdb0ac58dec6173b2ecd78f89fe))
* **mcpproxy:** Phase 2 — in-process OPA policy evaluation on tools/call ([1acbc68](https://github.com/jlgore/agentcontainers/commit/1acbc6833502866cbaca2a7f3c9068e4af3b3efc))
* **mcpproxy:** Phase 4 — human-in-the-loop approval ([7996f9e](https://github.com/jlgore/agentcontainers/commit/7996f9ed1cbb679b11c3b48fcb2ae3e2b24798a9))
* **mcpproxy:** support container backends over HTTP transport ([1209c46](https://github.com/jlgore/agentcontainers/commit/1209c46dee7fbeb2f3c1e1a38731d5bf98ebd86e))
* **scripts:** add bootstrap.sh for one-shot workstation setup ([31a862d](https://github.com/jlgore/agentcontainers/commit/31a862dc4e2e960f01c0592e7acee90af4dfef1d))


### Bug Fixes

* **ci:** fix SLSA provenance hash generation for goreleaser v2 ([4448458](https://github.com/jlgore/agentcontainers/commit/4448458d12adabcbffcb57e58c1860d3ad078330))
* **ci:** repair release workflow config ([58c26b2](https://github.com/jlgore/agentcontainers/commit/58c26b24a16d9fa635887f4863268f18d7cad7fc))
* **cli:** probe enforcer health eagerly at mcp start ([159d95b](https://github.com/jlgore/agentcontainers/commit/159d95b9225b86fed7a640cf22f2393ac54245ab))
* **ebpf:** gate the DNS ingress hook by ENFORCED_CGROUPS ([310720c](https://github.com/jlgore/agentcontainers/commit/310720cac20164dab45f86934ad0dc9ce38b314c))
* **enforcer:** bound and prune tool-call correlation windows ([4fe3f89](https://github.com/jlgore/agentcontainers/commit/4fe3f899057b33f4471a8f732091d3792d1b5714))
* **enforcer:** cgroup hooks never attached — AllowMultiple is EINVAL on bpf_link_create ([1958945](https://github.com/jlgore/agentcontainers/commit/195894581418e4d915d3191204d3b42105fa50f6))
* **enforcer:** deliver in-band gap marker when the event bus drops events ([40e2be4](https://github.com/jlgore/agentcontainers/commit/40e2be4c2d04f6582e133d9bba2b70893900f4b8))
* **enforcer:** drain DNS_EVENTS — DNS observation was dead end-to-end ([6d2882a](https://github.com/jlgore/agentcontainers/commit/6d2882a114acf7d29c2a48ee8b0b42b876b46c20))
* **enforcer:** get ac_dns_ingress under the verifier (non-elidable masks, offset normalization) ([9a261db](https://github.com/jlgore/agentcontainers/commit/9a261db27e02ccf0477f2ca7a615a4d61cb0d952))
* **enforcer:** grant the sidecar CAP_SYS_PTRACE so secret injection works ([ac99c64](https://github.com/jlgore/agentcontainers/commit/ac99c64df9bffbe80563fd8d6cf553cfa580c3e8))
* **enforcer:** make DNS observation degrade gracefully; rework parser for the verifier ([3b4518e](https://github.com/jlgore/agentcontainers/commit/3b4518e7d60af205634fc25e1d25fa1558089ad2))
* **enforcer:** make FsInodeKey lookups actually match — dev_t decode + container-namespace path resolution ([9b86c5b](https://github.com/jlgore/agentcontainers/commit/9b86c5ba19ea249c6ccf32d2b263b7bbdbfe54c8))
* **enforcer:** own injected secrets by the agent's uid, not root ([8540db6](https://github.com/jlgore/agentcontainers/commit/8540db6dfa4a36a6606f6426768ceb20c9981ea5))
* **enforcer:** own ring buffers in the reader (was UAF); move DNS identification to userspace ([0db833c](https://github.com/jlgore/agentcontainers/commit/0db833c85ff32c2a4571484fe6a156dfdd6e5e94))
* **enforcer:** park drained events briefly to close the prepare-side correlation race ([38eb27c](https://github.com/jlgore/agentcontainers/commit/38eb27c1c29b6a3ea4a9722e90fa8ae321babe8d))
* **enforcer:** populate BLOCKED_CIDRS and ALLOWED_V6 — always-deny was dead code ([e2d65d0](https://github.com/jlgore/agentcontainers/commit/e2d65d0c6eef78a6203925379af75b5c84dea6e4))
* **enforcer:** re-applying network policy replaces the IP set instead of accumulating ([7d3fa89](https://github.com/jlgore/agentcontainers/commit/7d3fa894a7932dee722396a25c44022e4eae3fec))
* **enforcer:** report partial network-policy application to the proxy ([8be9ade](https://github.com/jlgore/agentcontainers/commit/8be9ade4e06bc7fad5f830295c5208857ce03380))
* **mcpproxy:** clean up phase 1 gaps ([9a0e00f](https://github.com/jlgore/agentcontainers/commit/9a0e00f601b0143e6f60b87552fe6c992a2f3728))
* **mcpproxy:** enforce policy.filesystem at the proxy; review fixes ([d1003f6](https://github.com/jlgore/agentcontainers/commit/d1003f612abcff04f3363f3ab9e8e929335577dc))
* **mcpproxy:** freeze stdio backend on start to close the unenforced window ([fde4b97](https://github.com/jlgore/agentcontainers/commit/fde4b976fd0ec17eb12001fc64059631ef81e859))
* **mcpproxy:** reconnect the enforcer audit stream; record gaps in the chain ([17434a1](https://github.com/jlgore/agentcontainers/commit/17434a185e1621ddff5e02acbd9caf5db80a61e5))
* **mcpproxy:** roll back enforcer registration on partial failure ([961fbfc](https://github.com/jlgore/agentcontainers/commit/961fbfceb80b6ab84d266efba4e91c43ae36c844))
* **mcpproxy:** surface proxy-only posture of filesystem allowlists ([f607f4e](https://github.com/jlgore/agentcontainers/commit/f607f4e6e5252f38844ff4a38a5c87abc6c49d66))
* **oci:** resolve multi-arch image indexes in policy manifest fetch ([5e8aa87](https://github.com/jlgore/agentcontainers/commit/5e8aa87ef9456ba54c02810ab462ad7f829406cf))
* replace remaining ac-enforcer and ac CLI references in Go source ([aaf7667](https://github.com/jlgore/agentcontainers/commit/aaf76670e9d128f7ef558312abbe3163997e851e))
* **run:** attach egress-enabled agents to a user-defined bridge for DNS ([fd83c2f](https://github.com/jlgore/agentcontainers/commit/fd83c2f7f8d3bbe81e327a9cb716b066fdd319fd))
* **sec:** address spec-review findings on the 5 hardening PRs ([0af1114](https://github.com/jlgore/agentcontainers/commit/0af1114dc6b1f934cc03dd52eaadac5432989898))
* **test:** eliminate race in enforcer liveness test ([9c3bee7](https://github.com/jlgore/agentcontainers/commit/9c3bee729b9d5c8e9f734d4fd679047ecc93e639))
