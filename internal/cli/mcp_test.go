package cli

import (
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
)

// withEnforcerProbe swaps the eager health probe for the test's duration.
func withEnforcerProbe(t *testing.T, probe func(string) bool) *int {
	t.Helper()
	calls := new(int)
	orig := enforcerHealthProbe
	enforcerHealthProbe = func(addr string) bool {
		*calls++
		return probe(addr)
	}
	t.Cleanup(func() { enforcerHealthProbe = orig })
	return calls
}

func mcpDepsConfig(enforcerRequired *bool) *config.AgentContainer {
	return &config.AgentContainer{
		Agent: &config.AgentConfig{
			Enforcer: &config.EnforcerConfig{Required: enforcerRequired},
			Tools: &config.ToolsConfig{
				MCP: map[string]config.MCPToolConfig{
					"sift": {Type: "container", Image: "example/mcp:latest"},
				},
			},
		},
	}
}

// An unreachable enforcer with enforcement required must fail at mcp start
// (buildMCPDeps), not at first backend launch — grpc.NewClient is lazy and
// would otherwise defer the failure past audit/approval setup.
func TestBuildMCPDepsFailsEagerlyWhenEnforcerUnreachable(t *testing.T) {
	calls := withEnforcerProbe(t, func(string) bool { return false })

	_, cleanup, err := buildMCPDeps(mcpDepsConfig(nil), zap.NewNop())
	defer cleanup()

	if err == nil {
		t.Fatal("expected buildMCPDeps to fail with an unreachable enforcer")
	}
	if !strings.Contains(err.Error(), "health check") {
		t.Errorf("error should name the failed health check, got: %v", err)
	}
	if *calls != 1 {
		t.Errorf("health probe calls = %d, want 1", *calls)
	}
}

func TestBuildMCPDepsConnectsWhenEnforcerHealthy(t *testing.T) {
	calls := withEnforcerProbe(t, func(string) bool { return true })

	deps, cleanup, err := buildMCPDeps(mcpDepsConfig(nil), zap.NewNop())
	defer cleanup()

	if err != nil {
		t.Fatalf("buildMCPDeps: %v", err)
	}
	if deps.Enforcer == nil {
		t.Error("expected an enforcer client when the health probe passes")
	}
	if *calls != 1 {
		t.Errorf("health probe calls = %d, want 1", *calls)
	}
}

// enforcer.required: false opts out of kernel enforcement entirely — no
// probe, no client, no startup failure.
func TestBuildMCPDepsSkipsProbeWhenEnforcerDisabled(t *testing.T) {
	calls := withEnforcerProbe(t, func(string) bool { return false })

	disabled := false
	deps, cleanup, err := buildMCPDeps(mcpDepsConfig(&disabled), zap.NewNop())
	defer cleanup()

	if err != nil {
		t.Fatalf("buildMCPDeps: %v", err)
	}
	if deps.Enforcer != nil {
		t.Error("no enforcer client expected when enforcer.required is false")
	}
	if *calls != 0 {
		t.Errorf("health probe calls = %d, want 0", *calls)
	}
}
