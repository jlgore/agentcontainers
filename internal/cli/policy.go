package cli

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/mcpproxy"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/oci"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/orgpolicy"
)

func newPolicyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Manage organization security policies",
		Long: `Manage org-level security policies embedded in container images.

Policies define organizational constraints (required signatures, SLSA
levels, trusted registries, etc.) that workspace configurations must
satisfy. They are baked into container images as a typed layer at build
time via 'ac build --policy'.`,
	}
	cmd.AddCommand(
		newPolicyValidateCmd(),
		newPolicyDiffCmd(),
		newPolicyTrustCmd(),
		newPolicyTranslateCmd(),
		newPolicyVerifyCmd(),
	)
	return cmd
}

// newPolicyTranslateCmd returns "ac policy translate <securityYaml>", which
// compiles a security.yaml and dumps the Cedar policies + schema the Cedar
// backend (policy.engine: cedar) would evaluate. Pure emission — it does not
// need the cedar binary.
func newPolicyTranslateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "translate <securityYaml>",
		Short: "Compile a security.yaml and emit the equivalent Cedar policies + schema",
		Long: `Compile a security.yaml policy and print the Cedar policies and schema
that the Cedar authorization backend (policy.engine: cedar) would evaluate.

Only the structured-membership categories (denied_binaries, dangerous_flags,
tool_blocked_flags, capabilities) are translated to Cedar; path and content
(regex/substring) categories are evaluated by the native-Go evaluators that run
alongside the Cedar engine and so are not emitted here.

This is pure emission and does not require the Cedar CLI to be installed.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPolicyTranslate(cmd, args[0])
		},
	}
}

func runPolicyTranslate(cmd *cobra.Command, securityYAML string) error {
	sec, err := mcpproxy.LoadSecurityYAML(securityYAML)
	if err != nil {
		return fmt.Errorf("policy translate: %w", err)
	}
	cp, err := mcpproxy.Compile(sec, nil)
	if err != nil {
		return fmt.Errorf("policy translate: %w", err)
	}
	out := cmd.OutOrStdout()
	_, _ = fmt.Fprintln(out, "// ===== Cedar policies =====")
	_, _ = fmt.Fprintln(out, cp.CedarPolicies)
	_, _ = fmt.Fprintln(out, "// ===== Cedar schema =====")
	_, _ = fmt.Fprintln(out, cp.CedarSchema)
	return nil
}

// newPolicyVerifyCmd returns "ac policy verify <securityYaml>", which parses the
// emitted Cedar policies in-process (embedded cedar-go) and runs a
// representative authorize to confirm the membership policies enforce. No
// external binary is required, so it always runs.
func newPolicyVerifyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "verify <securityYaml>",
		Short: "Validate the emitted Cedar policies and check a representative invariant",
		Long: `Compile a security.yaml to Cedar, parse the emitted policies with the
embedded Cedar engine, then exercise a representative authorize to confirm the
membership policies actually enforce (e.g. a denied binary is denied).

Runs entirely in-process via embedded cedar-go — no external Cedar CLI is
required.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPolicyVerify(cmd, args[0])
		},
	}
}

func runPolicyVerify(cmd *cobra.Command, securityYAML string) error {
	sec, err := mcpproxy.LoadSecurityYAML(securityYAML)
	if err != nil {
		return fmt.Errorf("policy verify: %w", err)
	}
	cp, err := mcpproxy.Compile(sec, nil)
	if err != nil {
		return fmt.Errorf("policy verify: %w", err)
	}
	out := cmd.OutOrStdout()

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	// Representative invariant: a denied binary must be denied. Falls back to
	// confirming an innocuous binary is allowed when no denylist is declared.
	// Building the engine (inside CedarCheck) parses the emitted policies, so a
	// malformed emission fails here.
	if binary := firstDeniedBinary(cp); binary != "" {
		allowed, reasons, err := mcpproxy.CedarCheck(ctx, cp, binary, nil)
		if err != nil {
			return fmt.Errorf("policy verify: representative authorize: %w", err)
		}
		if allowed {
			return fmt.Errorf("policy verify: invariant FAILED: denied binary %q was allowed", binary)
		}
		_, _ = fmt.Fprintf(out, "invariant OK: denied binary %q is denied (%s)\n", binary, strings.Join(reasons, "; "))
		return nil
	}

	allowed, _, err := mcpproxy.CedarCheck(ctx, cp, "echo", nil)
	if err != nil {
		return fmt.Errorf("policy verify: representative authorize: %w", err)
	}
	if !allowed {
		return fmt.Errorf("policy verify: invariant FAILED: innocuous binary \"echo\" was denied")
	}
	_, _ = fmt.Fprintln(out, "invariant OK: innocuous binary \"echo\" is allowed (no denylist declared)")
	return nil
}

// firstDeniedBinary returns a denied binary from the compiled data, or "" if
// none is declared. denied_binaries is the lowercased, sorted denylist.
func firstDeniedBinary(cp *mcpproxy.CompiledPolicy) string {
	switch xs := cp.Data["denied_binaries"].(type) {
	case []string:
		if len(xs) > 0 {
			return xs[0]
		}
	case []any:
		if len(xs) > 0 {
			if s, ok := xs[0].(string); ok {
				return s
			}
		}
	}
	return ""
}

// newPolicyValidateCmd returns the "agentcontainer policy validate <file>" command which
// loads and validates a local policy file without pushing it.
func newPolicyValidateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate <file>",
		Short: "Validate a local org policy file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPolicyValidate(cmd, args[0])
		},
	}
}

func runPolicyValidate(cmd *cobra.Command, filePath string) error {
	if _, err := orgpolicy.LoadPolicy(filePath); err != nil {
		return fmt.Errorf("policy validate: %w", err)
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Policy valid: %s\n", filePath)
	return nil
}

// newPolicyDiffCmd returns the "agentcontainer policy diff <ref1> <ref2>" command which
// compares the policy layer embedded in two image references (PRD-017).
// Exits non-zero if the policies differ (useful in CI).
func newPolicyDiffCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "diff <ref1> <ref2>",
		Short: "Diff the org policy layer between two image references",
		Long: `Extract and compare the org policy layers from two OCI image references.

Exits 0 when the policies are identical, non-zero when they differ.
Useful in CI before promoting a new base image to review policy changes.

Examples:
  agentcontainer policy diff ghcr.io/myorg/base:v1 ghcr.io/myorg/base:v2
  agentcontainer policy diff ghcr.io/myorg/base@sha256:abc ghcr.io/myorg/base@sha256:def`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPolicyDiff(cmd, args[0], args[1])
		},
	}
}

func runPolicyDiff(cmd *cobra.Command, ref1, ref2 string) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	// Extract policy from first image.
	pol1, err := orgpolicy.ExtractPolicy(ctx, ref1)
	if err != nil {
		return fmt.Errorf("policy diff: extracting policy from %s: %w", ref1, err)
	}

	// Extract policy from second image.
	pol2, err := orgpolicy.ExtractPolicy(ctx, ref2)
	if err != nil {
		return fmt.Errorf("policy diff: extracting policy from %s: %w", ref2, err)
	}

	json1, err := json.MarshalIndent(pol1, "", "  ")
	if err != nil {
		return fmt.Errorf("policy diff: marshaling policy from %s: %w", ref1, err)
	}
	json2, err := json.MarshalIndent(pol2, "", "  ")
	if err != nil {
		return fmt.Errorf("policy diff: marshaling policy from %s: %w", ref2, err)
	}

	out := cmd.OutOrStdout()
	_, _ = fmt.Fprintf(out, "--- %s\n%s\n", ref1, json1)
	_, _ = fmt.Fprintf(out, "+++ %s\n%s\n", ref2, json2)

	if string(json1) == string(json2) {
		_, _ = fmt.Fprintln(out, "Policies are identical.")
		return nil
	}

	return fmt.Errorf("policies differ")
}

// newPolicyTrustCmd returns the "agentcontainer policy trust" command group for managing
// the local org policy trust store (~/.agentcontainers/trusted-org-keys.json).
func newPolicyTrustCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "trust",
		Short: "Manage trusted org policy signing keys",
		Long: `Manage the local trust store for org policy signing keys.

The trust store (~/.agentcontainers/trusted-org-keys.json, or AC_ORG_TRUST_STORE
env var) holds the Ed25519 public keys that are trusted to sign org policy layers
baked into container images. At runtime, agentcontainer run uses these keys to validate the
policy layer embedded in the container image before applying it.

When the trust store is populated, policy layers not signed by a trusted key are
skipped (non-strict) or rejected (--strict). This separates org signing authority
from image push rights: a developer with registry write access cannot inject a
permissive policy layer that bypasses enforcement.`,
	}
	cmd.AddCommand(
		newPolicyTrustAddCmd(),
		newPolicyTrustListCmd(),
		newPolicyTrustRemoveCmd(),
	)
	return cmd
}

func newPolicyTrustAddCmd() *cobra.Command {
	var (
		storePath string
		comment   string
	)
	cmd := &cobra.Command{
		Use:   "add <keyfile>",
		Short: "Add a trusted org policy signing key",
		Long: `Add an Ed25519 public key to the local org policy trust store.

<keyfile> may be:
  - A PEM file containing a PKIX/SubjectPublicKeyInfo Ed25519 public key
  - A raw 32-byte binary Ed25519 public key file

The key is identified by the SHA-256 fingerprint (keyid) of its raw bytes.
Use 'ac policy trust list' to see the stored keys after adding.

Examples:
  agentcontainer policy trust add org-policy.pub
  agentcontainer policy trust add /etc/agentcontainers/org.pub --comment "Acme Corp policy key"`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPolicyTrustAdd(cmd, args[0], storePath, comment)
		},
	}
	cmd.Flags().StringVar(&storePath, "store", "", "Path to trust store (default: ~/.agentcontainers/trusted-org-keys.json)")
	cmd.Flags().StringVar(&comment, "comment", "", "Human-readable label for the key")
	return cmd
}

func runPolicyTrustAdd(cmd *cobra.Command, keyFilePath, storePath, comment string) error {
	pub, err := loadEd25519PublicKey(keyFilePath)
	if err != nil {
		return fmt.Errorf("policy trust add: %w", err)
	}

	if storePath == "" {
		storePath, err = oci.DefaultTrustStorePath()
		if err != nil {
			return fmt.Errorf("policy trust add: %w", err)
		}
	}

	ts, err := oci.LoadTrustStore(storePath)
	if err != nil {
		return fmt.Errorf("policy trust add: %w", err)
	}

	keyID := ts.AddKey(pub, comment)

	if err := oci.SaveTrustStore(storePath, ts); err != nil {
		return fmt.Errorf("policy trust add: %w", err)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Added key %s to %s\n", keyID, storePath)
	return nil
}

func newPolicyTrustListCmd() *cobra.Command {
	var storePath string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List trusted org policy signing keys",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPolicyTrustList(cmd, storePath)
		},
	}
	cmd.Flags().StringVar(&storePath, "store", "", "Path to trust store (default: ~/.agentcontainers/trusted-org-keys.json)")
	return cmd
}

func runPolicyTrustList(cmd *cobra.Command, storePath string) error {
	var err error
	if storePath == "" {
		storePath, err = oci.DefaultTrustStorePath()
		if err != nil {
			return fmt.Errorf("policy trust list: %w", err)
		}
	}

	ts, err := oci.LoadTrustStore(storePath)
	if err != nil {
		return fmt.Errorf("policy trust list: %w", err)
	}

	out := cmd.OutOrStdout()
	if len(ts.Keys) == 0 {
		_, _ = fmt.Fprintln(out, "No trusted org keys.")
		return nil
	}

	for _, e := range ts.Keys {
		if e.Comment != "" {
			_, _ = fmt.Fprintf(out, "%s  # %s\n", e.KeyID, e.Comment)
		} else {
			_, _ = fmt.Fprintln(out, e.KeyID)
		}
	}
	return nil
}

func newPolicyTrustRemoveCmd() *cobra.Command {
	var storePath string
	cmd := &cobra.Command{
		Use:   "remove <keyid>",
		Short: "Remove a trusted org policy signing key by key ID",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPolicyTrustRemove(cmd, args[0], storePath)
		},
	}
	cmd.Flags().StringVar(&storePath, "store", "", "Path to trust store (default: ~/.agentcontainers/trusted-org-keys.json)")
	return cmd
}

func runPolicyTrustRemove(cmd *cobra.Command, keyID, storePath string) error {
	var err error
	if storePath == "" {
		storePath, err = oci.DefaultTrustStorePath()
		if err != nil {
			return fmt.Errorf("policy trust remove: %w", err)
		}
	}

	ts, err := oci.LoadTrustStore(storePath)
	if err != nil {
		return fmt.Errorf("policy trust remove: %w", err)
	}

	newKeys := ts.Keys[:0]
	removed := false
	for _, e := range ts.Keys {
		if e.KeyID == keyID {
			removed = true
			continue
		}
		newKeys = append(newKeys, e)
	}
	if !removed {
		return fmt.Errorf("policy trust remove: key %q not found in trust store", keyID)
	}
	ts.Keys = newKeys

	if err := oci.SaveTrustStore(storePath, ts); err != nil {
		return fmt.Errorf("policy trust remove: %w", err)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Removed key %s from %s\n", keyID, storePath)
	return nil
}

// loadEd25519PublicKey reads an Ed25519 public key from path.
// Supports PEM-encoded PKIX/SubjectPublicKeyInfo and raw 32-byte files.
func loadEd25519PublicKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading public key file: %w", err)
	}

	// Try PEM first.
	block, _ := pem.Decode(data)
	if block != nil {
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing PEM public key: %w", err)
		}
		ed, ok := pub.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("key is not an Ed25519 public key (got %T)", pub)
		}
		return ed, nil
	}

	// Fallback: raw 32-byte public key.
	if len(data) == ed25519.PublicKeySize {
		return ed25519.PublicKey(data), nil
	}

	return nil, fmt.Errorf("unrecognized key format in %q: expected PEM PUBLIC KEY block or %d-byte raw key", path, ed25519.PublicKeySize)
}
