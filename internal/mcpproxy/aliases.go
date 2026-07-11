package mcpproxy

// This file re-exports the tool-call policy engine that now lives in
// internal/toolpolicy, so the mcpproxy runtime files and external consumers
// (internal/guard, internal/cli) keep referring to mcpproxy.X unchanged. The
// policy engine was extracted into its own package to decouple it from the
// proxy runtime; these aliases are the compatibility shim across that seam.

import "github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/toolpolicy"

// Types.
type (
	Parsed          = toolpolicy.Parsed
	Decision        = toolpolicy.Decision
	EgressTarget    = toolpolicy.EgressTarget
	PolicyEngine    = toolpolicy.PolicyEngine
	CompiledPolicy  = toolpolicy.CompiledPolicy
	SecurityPolicy  = toolpolicy.SecurityPolicy
	GuardPolicyFile = toolpolicy.GuardPolicyFile
)

// Functions and values.
var (
	Compile               = toolpolicy.Compile
	CompileServerPolicy   = toolpolicy.CompileServerPolicy
	DecomposeCommand      = toolpolicy.DecomposeCommand
	DecomposeShellLine    = toolpolicy.DecomposeShellLine
	DecomposeWrapped      = toolpolicy.DecomposeWrapped
	NewCedarEvaluator     = toolpolicy.NewCedarEvaluator
	CedarCheck            = toolpolicy.CedarCheck
	LoadGuardPolicyYAML   = toolpolicy.LoadGuardPolicyYAML
	LoadSecurityYAML      = toolpolicy.LoadSecurityYAML
	DefaultSecurityPolicy = toolpolicy.DefaultSecurityPolicy
	DefaultOutputFlags    = toolpolicy.DefaultOutputFlags
	ExtractRequestedURIs  = toolpolicy.ExtractRequestedURIs
	ExtractMetaURIs       = toolpolicy.ExtractMetaURIs
	EvaluateParsed        = toolpolicy.EvaluateParsed
)
