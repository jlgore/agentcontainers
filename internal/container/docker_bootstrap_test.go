package container

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
	"go.uber.org/zap"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/enforcement"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/policy"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/secrets"
)

// recordingDockerClient records the order of container lifecycle calls made by
// DockerRuntime.Start. Only the methods Start needs are implemented; anything
// else panics via the embedded APIClient.
type recordingDockerClient struct {
	client.APIClient
	rec      *[]string
	pauseErr error
}

func (c *recordingDockerClient) ImageInspect(_ context.Context, _ string, _ ...client.ImageInspectOption) (client.ImageInspectResult, error) {
	return client.ImageInspectResult{}, nil // image present, no pull
}

func (c *recordingDockerClient) ContainerCreate(_ context.Context, _ client.ContainerCreateOptions) (client.ContainerCreateResult, error) {
	return client.ContainerCreateResult{ID: "cid"}, nil
}

func (c *recordingDockerClient) ContainerStart(_ context.Context, _ string, _ client.ContainerStartOptions) (client.ContainerStartResult, error) {
	*c.rec = append(*c.rec, "start")
	return client.ContainerStartResult{}, nil
}

func (c *recordingDockerClient) ContainerPause(_ context.Context, _ string, _ client.ContainerPauseOptions) (client.ContainerPauseResult, error) {
	*c.rec = append(*c.rec, "pause")
	return client.ContainerPauseResult{}, c.pauseErr
}

func (c *recordingDockerClient) ContainerInspect(_ context.Context, _ string, _ client.ContainerInspectOptions) (client.ContainerInspectResult, error) {
	*c.rec = append(*c.rec, "inspect")
	return client.ContainerInspectResult{
		Container: container.InspectResponse{State: &container.State{Pid: 1234}},
	}, nil
}

func (c *recordingDockerClient) ContainerUnpause(_ context.Context, _ string, _ client.ContainerUnpauseOptions) (client.ContainerUnpauseResult, error) {
	*c.rec = append(*c.rec, "unpause")
	return client.ContainerUnpauseResult{}, nil
}

func (c *recordingDockerClient) ContainerStop(_ context.Context, _ string, _ client.ContainerStopOptions) (client.ContainerStopResult, error) {
	*c.rec = append(*c.rec, "stop")
	return client.ContainerStopResult{}, nil
}

func (c *recordingDockerClient) ContainerRemove(_ context.Context, _ string, _ client.ContainerRemoveOptions) (client.ContainerRemoveResult, error) {
	*c.rec = append(*c.rec, "remove")
	return client.ContainerRemoveResult{}, nil
}

// recordingStrategy records its enforcement calls into the same slice as the
// docker client, and can be configured to fail at a chosen stage.
type recordingStrategy struct {
	rec     *[]string
	failAt  string // "base", "inject", "acl", or ""
	removed bool
}

func (s *recordingStrategy) record(stage string) error {
	*s.rec = append(*s.rec, stage)
	if s.failAt == stage {
		return errors.New("forced failure at " + stage)
	}
	return nil
}

func (s *recordingStrategy) Apply(_ context.Context, _ string, _ uint32, _ *policy.ContainerPolicy) error {
	return nil
}
func (s *recordingStrategy) ApplyBasePolicy(_ context.Context, _ string, _ uint32, _ *policy.ContainerPolicy) error {
	return s.record("base")
}
func (s *recordingStrategy) ApplyCredentialACLs(_ context.Context, _ string, _ *policy.ContainerPolicy) error {
	return s.record("acl")
}
func (s *recordingStrategy) InjectSecrets(_ context.Context, _ string, _ map[string]*secrets.Secret) error {
	return s.record("inject")
}
func (s *recordingStrategy) Update(_ context.Context, _ string, _ *policy.ContainerPolicy) error {
	return nil
}
func (s *recordingStrategy) Remove(_ context.Context, _ string) error {
	*s.rec = append(*s.rec, "enforcement-remove")
	s.removed = true
	return nil
}
func (s *recordingStrategy) Events(_ string) <-chan enforcement.Event { return nil }
func (s *recordingStrategy) Level() enforcement.Level                 { return enforcement.LevelGRPC }

var _ enforcement.Strategy = (*recordingStrategy)(nil)

func bootstrapTestRuntime(rec *[]string, strat *recordingStrategy, pauseErr error) *DockerRuntime {
	return &DockerRuntime{
		client:   &recordingDockerClient{APIClient: nil, rec: rec, pauseErr: pauseErr},
		logger:   zap.NewNop(),
		strategy: strat,
	}
}

func bootstrapStartOpts() (*config.AgentContainer, StartOptions) {
	cfg := &config.AgentContainer{Name: "boot-test", Image: "alpine:3.19"}
	opts := StartOptions{
		Policy: &policy.ContainerPolicy{NetworkMode: "none"},
		ResolvedSecrets: map[string]*secrets.Secret{
			"API_KEY": {Value: []byte("v")},
		},
	}
	return cfg, opts
}

// TestDockerStart_BootstrapOrdering asserts the exact paused-bootstrap sequence:
// the container is paused before any policy/secret work, secrets are injected
// before ACLs, and the container is unpaused only at the very end.
func TestDockerStart_BootstrapOrdering(t *testing.T) {
	var rec []string
	strat := &recordingStrategy{rec: &rec}
	rt := bootstrapTestRuntime(&rec, strat, nil)

	cfg, opts := bootstrapStartOpts()
	if _, err := rt.Start(context.Background(), cfg, opts); err != nil {
		t.Fatalf("Start: %v", err)
	}

	want := []string{"start", "pause", "inspect", "base", "inject", "acl", "unpause"}
	if strings.Join(rec, ",") != strings.Join(want, ",") {
		t.Fatalf("bootstrap order = %v, want %v", rec, want)
	}
}

// TestDockerStart_FailClosedNeverUnpauses asserts that a failure at any bootstrap
// stage tears the container down (force remove) and never unpauses it.
func TestDockerStart_FailClosedNeverUnpauses(t *testing.T) {
	stages := []struct {
		name   string
		failAt string
	}{
		{"base policy", "base"},
		{"inject secrets", "inject"},
		{"credential ACLs", "acl"},
	}
	for _, st := range stages {
		t.Run(st.name, func(t *testing.T) {
			var rec []string
			strat := &recordingStrategy{rec: &rec, failAt: st.failAt}
			rt := bootstrapTestRuntime(&rec, strat, nil)

			cfg, opts := bootstrapStartOpts()
			if _, err := rt.Start(context.Background(), cfg, opts); err == nil {
				t.Fatal("expected Start to fail")
			}

			joined := strings.Join(rec, ",")
			if strings.Contains(joined, "unpause") {
				t.Errorf("must never unpause on failure; got %v", rec)
			}
			if !contains(rec, "remove") {
				t.Errorf("expected container force-remove on failure; got %v", rec)
			}
			if !strat.removed {
				t.Errorf("expected enforcement removal on failure; got %v", rec)
			}
		})
	}
}

// TestDockerStart_PauseFailureTearsDown asserts a pause failure is fatal and the
// container is removed without ever running unenforced.
func TestDockerStart_PauseFailureTearsDown(t *testing.T) {
	var rec []string
	strat := &recordingStrategy{rec: &rec}
	rt := bootstrapTestRuntime(&rec, strat, errors.New("pause boom"))

	cfg, opts := bootstrapStartOpts()
	if _, err := rt.Start(context.Background(), cfg, opts); err == nil {
		t.Fatal("expected Start to fail on pause error")
	}
	if contains(rec, "unpause") || contains(rec, "base") {
		t.Errorf("no enforcement or unpause should occur after pause failure; got %v", rec)
	}
	if !contains(rec, "remove") {
		t.Errorf("expected force-remove after pause failure; got %v", rec)
	}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
