package main

import (
	"os"
)

// Config is the worker's runtime configuration, all from the environment so the
// same binary runs locally (against a port-forward / explicit GUEST_HOST) and
// in-cluster (resolving the VMI pod IP via the KubeVirt API). Sane in-cluster
// defaults; every value overridable.
type Config struct {
	// Temporal
	HostPort  string // temporal frontend gRPC
	Namespace string // temporal namespace
	TaskQueue string

	// Guest (KubeVirt VMI) access
	VMNamespace string // k8s ns holding the VM/VMI
	VMName      string // VM/VMI name
	GuestHost   string // explicit host:port override; empty => resolve VMI pod IP
	SSHUser     string
	SSHKeyPath  string
	RemoteDir   string // where breakout-run.sh + friends live on the guest
	AuditDir    string // guest audit dir the runner writes

	// Provider key: dynamic (default) via the vault-openrouter-engine, or a
	// static override for local runs without Vault.
	//
	// If ProviderKey is set, it is used verbatim and no Vault call is made.
	// Otherwise the worker logs in to Vault with its k8s SA (VaultRole on the
	// VaultK8sMount) and mints a budget-capped, lease-backed key from
	// <OpenRouterMount>/creds/<OpenRouterRole>, revoking it when the drive ends.
	ProviderKey     string
	VaultAddr       string
	VaultK8sMount   string
	VaultRole       string
	OpenRouterMount string
	OpenRouterRole  string

	// Loki push endpoint (in-cluster service).
	LokiURL string
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func loadConfig() Config {
	return Config{
		HostPort:  env("TEMPORAL_HOSTPORT", "temporal-frontend.temporal.svc.cluster.local:7233"),
		Namespace: env("TEMPORAL_NAMESPACE", "escape-harness"),
		TaskQueue: env("TASK_QUEUE", "escape-cells"),

		VMNamespace: env("VM_NAMESPACE", "ac-matrix"),
		VMName:      env("VM_NAME", "ac-matrix-vm"),
		GuestHost:   env("GUEST_HOST", ""),
		SSHUser:     env("SSH_USER", "ubuntu"),
		SSHKeyPath:  env("SSH_KEY_PATH", "/run/secrets/ac-matrix/ssh-key"),
		RemoteDir:   env("REMOTE_DIR", "/home/ubuntu/breakout"),
		AuditDir:    env("AC_AUDIT_DIR", "/var/lib/ac/audit"),

		ProviderKey:     os.Getenv("PROVIDER_KEY"),
		VaultAddr:       env("VAULT_ADDR", "http://vault.vault.svc.cluster.local:8200"),
		VaultK8sMount:   env("VAULT_K8S_MOUNT", "kubernetes"),
		VaultRole:       env("VAULT_ROLE", "harness-worker"),
		OpenRouterMount: env("OPENROUTER_MOUNT", "openrouter"),
		OpenRouterRole:  env("OPENROUTER_ROLE", "escape-harness"),

		LokiURL: env("LOKI_URL", "http://loki.monitoring.svc.cluster.local:3100"),
	}
}
