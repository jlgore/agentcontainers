package orgpolicy

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
)

// MergePolicy validates that a workspace configuration satisfies the
// organizational policy constraints. It returns an error describing all
// violations, or nil if the workspace is compliant.
func MergePolicy(org *OrgPolicy, workspace *config.AgentContainer) error {
	if org == nil || workspace == nil {
		return nil
	}

	var errs []error

	caps := extractCapabilityNames(workspace)
	errs = append(errs, checkAllowed(org, caps)...)
	errs = append(errs, checkDenied(org, caps)...)
	errs = append(errs, checkMCPImages(org, workspace)...)
	errs = append(errs, checkFilesystemPaths(org, workspace)...)
	errs = append(errs, checkNetworkHosts(org, workspace)...)

	return errors.Join(errs...)
}

// extractCapabilityNames returns the set of capability category names that
// are active in the workspace configuration. These are the top-level
// capability sections: "filesystem", "network", "shell", "git".
func extractCapabilityNames(ws *config.AgentContainer) []string {
	if ws.Agent == nil || ws.Agent.Capabilities == nil {
		return nil
	}

	var names []string
	c := ws.Agent.Capabilities

	if c.Filesystem != nil {
		names = append(names, "filesystem")
	}
	if c.Network != nil {
		names = append(names, "network")
	}
	if c.Shell != nil {
		names = append(names, "shell")
	}
	if c.Git != nil {
		names = append(names, "git")
	}

	return names
}

// checkAllowed verifies that all workspace capabilities are in the org's
// AllowedCapabilities list. If AllowedCapabilities is empty, all
// capabilities are permitted (open-by-default).
func checkAllowed(org *OrgPolicy, caps []string) []error {
	if len(org.AllowedCapabilities) == 0 {
		return nil
	}

	allowed := make(map[string]bool, len(org.AllowedCapabilities))
	for _, c := range org.AllowedCapabilities {
		allowed[c] = true
	}

	var errs []error
	for _, c := range caps {
		if !allowed[c] {
			errs = append(errs, fmt.Errorf("capability %q is not allowed by org policy", c))
		}
	}

	return errs
}

// checkMCPImages verifies that all MCP server images in the workspace
// are on the org policy's AllowedMCPImages list.
func checkMCPImages(org *OrgPolicy, ws *config.AgentContainer) []error {
	if len(org.AllowedMCPImages) == 0 {
		return nil
	}
	if ws.Agent == nil || ws.Agent.Tools == nil {
		return nil
	}

	var errs []error
	for name, mcp := range ws.Agent.Tools.MCP {
		if !MatchesMCPAllowlist(mcp.Image, org.AllowedMCPImages) {
			errs = append(errs, fmt.Errorf("mcp %q image %q is not in org policy allowedMCPImages", name, mcp.Image))
		}
	}
	return errs
}

// checkDenied verifies that no workspace capabilities are in the org's
// DeniedCapabilities list. Deny always wins.
func checkDenied(org *OrgPolicy, caps []string) []error {
	if len(org.DeniedCapabilities) == 0 {
		return nil
	}

	denied := make(map[string]bool, len(org.DeniedCapabilities))
	for _, c := range org.DeniedCapabilities {
		denied[c] = true
	}

	var errs []error
	for _, c := range caps {
		if denied[c] {
			errs = append(errs, fmt.Errorf("capability %q is denied by org policy", c))
		}
	}

	return errs
}

// checkFilesystemPaths verifies that all filesystem paths declared by the
// workspace are sub-paths of at least one path in AllowedFilesystemPaths.
// When AllowedFilesystemPaths is empty, all paths are permitted (F-5 fix).
func checkFilesystemPaths(org *OrgPolicy, ws *config.AgentContainer) []error {
	if len(org.AllowedFilesystemPaths) == 0 {
		return nil
	}
	if ws.Agent == nil || ws.Agent.Capabilities == nil || ws.Agent.Capabilities.Filesystem == nil {
		return nil
	}

	fs := ws.Agent.Capabilities.Filesystem
	var all []string
	all = append(all, fs.Read...)
	all = append(all, fs.Write...)
	all = append(all, fs.Deny...)

	var errs []error
	for _, p := range all {
		if !pathPermittedByAllowlist(p, org.AllowedFilesystemPaths) {
			errs = append(errs, fmt.Errorf("filesystem path %q is not within any org-allowed path (allowedFilesystemPaths: %v)", p, org.AllowedFilesystemPaths))
		}
	}
	return errs
}

// pathPermittedByAllowlist returns true if p is equal to or a sub-path of
// at least one entry in the allowlist.
//
// Both the declared path and each allowlist entry are lexically cleaned
// (filepath.Clean) before comparison, and containment is checked with
// filepath.Rel rather than a raw string prefix. This prevents a declared
// path containing ".." (e.g. "/workspace/../../etc") from bypassing an
// allowlist of "/workspace": cleaning resolves it to "/etc", which Rel
// reports as escaping the allowed root. Note this is purely lexical and
// does not resolve symlinks.
func pathPermittedByAllowlist(p string, allowlist []string) bool {
	cleaned := filepath.Clean(p)
	for _, allowed := range allowlist {
		allowedClean := filepath.Clean(allowed)
		if cleaned == allowedClean {
			return true
		}
		rel, err := filepath.Rel(allowedClean, cleaned)
		if err != nil {
			// Mismatched absolute/relative forms cannot be compared; treat
			// as not permitted (consistent with the previous prefix check).
			continue
		}
		// rel must stay within allowedClean: it may not be ".." or start
		// with a "../" segment, which would indicate escaping the root.
		if rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// checkNetworkHosts verifies that all egress host declarations in the workspace
// are permitted by AllowedNetworkHosts. When AllowedNetworkHosts is empty, all
// hosts are permitted (F-5 fix for network capability).
func checkNetworkHosts(org *OrgPolicy, ws *config.AgentContainer) []error {
	if len(org.AllowedNetworkHosts) == 0 {
		return nil
	}
	if ws.Agent == nil || ws.Agent.Capabilities == nil || ws.Agent.Capabilities.Network == nil {
		return nil
	}

	var errs []error
	for _, rule := range ws.Agent.Capabilities.Network.Egress {
		if !hostPermittedByAllowlist(rule.Host, org.AllowedNetworkHosts) {
			errs = append(errs, fmt.Errorf("network egress host %q is not in org-allowed hosts (allowedNetworkHosts: %v)", rule.Host, org.AllowedNetworkHosts))
		}
	}
	return errs
}

// hostPermittedByAllowlist returns true if host matches any entry in the
// allowlist. Supports exact matches and suffix wildcards (*.example.com).
func hostPermittedByAllowlist(host string, allowlist []string) bool {
	for _, allowed := range allowlist {
		if host == allowed {
			return true
		}
		// Suffix wildcard: "*.example.com" matches "foo.example.com"
		if strings.HasPrefix(allowed, "*.") {
			suffix := allowed[1:] // ".example.com"
			if strings.HasSuffix(host, suffix) {
				return true
			}
		}
	}
	return false
}
