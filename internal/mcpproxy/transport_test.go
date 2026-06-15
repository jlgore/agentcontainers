package mcpproxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"

	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.uber.org/zap/zaptest"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
)

// muxFrame writes one stdcopy frame: an 8-byte header
// [streamType, 0, 0, 0, len(be32)] followed by the payload — the wire
// format a non-TTY Docker attach stream uses.
func muxFrame(buf *bytes.Buffer, stream stdcopy.StdType, payload string) {
	hdr := make([]byte, 8)
	hdr[0] = byte(stream)
	binary.BigEndian.PutUint32(hdr[4:], uint32(len(payload)))
	buf.Write(hdr)
	buf.WriteString(payload)
}

// TestStdcopyDemux validates the framing assumption behind the stdio
// container transport: a non-TTY Docker attach stream multiplexes
// stdout/stderr with stdcopy headers, and the demux goroutine must yield a
// clean stdout byte stream (stderr discarded) for MCP JSON-RPC framing.
func TestStdcopyDemux(t *testing.T) {
	// Simulate the container side: interleaved stdout/stderr frames.
	var muxed bytes.Buffer
	muxFrame(&muxed, stdcopy.Stderr, "starting up...\n")
	muxFrame(&muxed, stdcopy.Stdout, `{"jsonrpc":"2.0","id":1,"result":{}}`+"\n")
	muxFrame(&muxed, stdcopy.Stderr, "some log noise\n")
	muxFrame(&muxed, stdcopy.Stdout, `{"jsonrpc":"2.0","method":"notifications/x"}`+"\n")

	// The proxy side: demux exactly as dialStdioContainer does.
	stdoutR, stdoutW := io.Pipe()
	go func() {
		_, err := stdcopy.StdCopy(stdoutW, io.Discard, bufio.NewReader(&muxed))
		stdoutW.CloseWithError(err)
	}()

	scanner := bufio.NewScanner(stdoutR)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if len(lines) != 2 {
		t.Fatalf("expected 2 clean stdout lines, got %d: %v", len(lines), lines)
	}
	if lines[0] != `{"jsonrpc":"2.0","id":1,"result":{}}` {
		t.Errorf("line 0 = %q", lines[0])
	}
	if lines[1] != `{"jsonrpc":"2.0","method":"notifications/x"}` {
		t.Errorf("line 1 = %q", lines[1])
	}
}

func TestParseColonMounts(t *testing.T) {
	mounts := parseColonMounts([]string{
		"/opt/zimmerman:/opt/zimmerman:ro",
		"/cases:/cases",
		"invalid",
	})
	if len(mounts) != 2 {
		t.Fatalf("expected 2 mounts, got %d", len(mounts))
	}
	if mounts[0].Source != "/opt/zimmerman" || mounts[0].Target != "/opt/zimmerman" || !mounts[0].ReadOnly {
		t.Errorf("mounts[0] = %+v", mounts[0])
	}
	if mounts[1].Source != "/cases" || mounts[1].ReadOnly {
		t.Errorf("mounts[1] = %+v", mounts[1])
	}
}

func TestEnvList(t *testing.T) {
	if envList(nil) != nil {
		t.Error("nil env must produce nil list")
	}
	got := envList(map[string]string{"B": "2", "A": "1"})
	if len(got) != 2 || got[0] != "A=1" || got[1] != "B=2" {
		t.Errorf("envList = %v, want sorted [A=1 B=2]", got)
	}
}

func TestBackendEnforcement(t *testing.T) {
	if (&Backend{Kind: KindRemote}).Enforcement() != "proxy-only" {
		t.Error("remote backend must report proxy-only enforcement")
	}
	if (&Backend{Kind: KindStdio}).Enforcement() != "" {
		t.Error("container backend must report empty enforcement")
	}
}

type fakeDockerClient struct {
	client.APIClient

	createdConfig     *container.Config
	createdHostConfig *container.HostConfig
	networkName       string
	started           bool
	paused            bool
	unpaused          bool
	removed           bool
	pauseErr          error
	containerConn     net.Conn
}

func (f *fakeDockerClient) ImageInspect(context.Context, string, ...client.ImageInspectOption) (client.ImageInspectResult, error) {
	return client.ImageInspectResult{}, nil
}

func (f *fakeDockerClient) ImagePull(context.Context, string, client.ImagePullOptions) (client.ImagePullResponse, error) {
	return nil, errors.New("unexpected image pull")
}

func (f *fakeDockerClient) NetworkInspect(context.Context, string, client.NetworkInspectOptions) (client.NetworkInspectResult, error) {
	return client.NetworkInspectResult{}, errors.New("network not found")
}

func (f *fakeDockerClient) NetworkCreate(_ context.Context, name string, _ client.NetworkCreateOptions) (client.NetworkCreateResult, error) {
	f.networkName = name
	return client.NetworkCreateResult{ID: "network-1"}, nil
}

func (f *fakeDockerClient) ContainerCreate(_ context.Context, opts client.ContainerCreateOptions) (client.ContainerCreateResult, error) {
	f.createdConfig = opts.Config
	f.createdHostConfig = opts.HostConfig
	return client.ContainerCreateResult{ID: "container-1"}, nil
}

func (f *fakeDockerClient) ContainerAttach(context.Context, string, client.ContainerAttachOptions) (client.ContainerAttachResult, error) {
	hostConn, containerConn := net.Pipe()
	f.containerConn = containerConn
	return client.ContainerAttachResult{HijackedResponse: client.NewHijackedResponse(hostConn, "")}, nil
}

func (f *fakeDockerClient) ContainerStart(context.Context, string, client.ContainerStartOptions) (client.ContainerStartResult, error) {
	f.started = true
	// Only the stdio path attaches; the http path has no containerConn.
	if f.containerConn != nil {
		go func() {
			var muxed bytes.Buffer
			muxFrame(&muxed, stdcopy.Stderr, "log noise\n")
			muxFrame(&muxed, stdcopy.Stdout, `{"jsonrpc":"2.0","id":1,"result":{}}`+"\n")
			_, _ = f.containerConn.Write(muxed.Bytes())
			_ = f.containerConn.Close()
		}()
	}
	return client.ContainerStartResult{}, nil
}

func (f *fakeDockerClient) ContainerInspect(context.Context, string, client.ContainerInspectOptions) (client.ContainerInspectResult, error) {
	return client.ContainerInspectResult{
		Container: container.InspectResponse{
			NetworkSettings: &container.NetworkSettings{
				Networks: map[string]*network.EndpointSettings{
					f.networkName: {IPAddress: netip.MustParseAddr("172.20.0.42")},
				},
			},
		},
	}, nil
}

func (f *fakeDockerClient) ContainerPause(context.Context, string, client.ContainerPauseOptions) (client.ContainerPauseResult, error) {
	if f.pauseErr != nil {
		return client.ContainerPauseResult{}, f.pauseErr
	}
	f.paused = true
	return client.ContainerPauseResult{}, nil
}

func (f *fakeDockerClient) ContainerUnpause(context.Context, string, client.ContainerUnpauseOptions) (client.ContainerUnpauseResult, error) {
	f.unpaused = true
	return client.ContainerUnpauseResult{}, nil
}

func (f *fakeDockerClient) ContainerStop(context.Context, string, client.ContainerStopOptions) (client.ContainerStopResult, error) {
	return client.ContainerStopResult{}, nil
}

func (f *fakeDockerClient) ContainerRemove(context.Context, string, client.ContainerRemoveOptions) (client.ContainerRemoveResult, error) {
	f.removed = true
	return client.ContainerRemoveResult{}, nil
}

func TestDialStdioContainerUsesDockerAttachDemux(t *testing.T) {
	docker := &fakeDockerClient{}
	sc, err := dialStdioContainer(t.Context(), Deps{Docker: docker, Logger: zaptest.NewLogger(t)}, "sift", &config.ContainerTool{
		Image:   "example/mcp:latest",
		Command: []string{"mcp-server"},
		Env:     map[string]string{"B": "2", "A": "1"},
	}, "sessionabcdef", "ac-mcp-sessiona")
	if err != nil {
		t.Fatalf("dialStdioContainer: %v", err)
	}
	if sc.containerID != "container-1" {
		t.Fatalf("containerID = %q, want container-1", sc.containerID)
	}
	if docker.networkName != "ac-mcp-sessiona" {
		t.Fatalf("network = %q, want ac-mcp-sessiona", docker.networkName)
	}
	if !docker.started {
		t.Fatal("container was not started")
	}
	// The container must come back frozen so enforcement lands before it
	// runs; it must not be unpaused until the caller calls resume.
	if !docker.paused {
		t.Fatal("container was not frozen after start")
	}
	if docker.unpaused {
		t.Fatal("container was unfrozen before resume")
	}
	if docker.createdConfig == nil || docker.createdConfig.Tty {
		t.Fatalf("container config = %+v, want non-TTY config", docker.createdConfig)
	}
	if got := docker.createdConfig.Env; len(got) != 2 || got[0] != "A=1" || got[1] != "B=2" {
		t.Fatalf("env = %v, want sorted [A=1 B=2]", got)
	}
	assertHardenedMCPHostConfig(t, docker.createdHostConfig)

	if err := sc.resume(t.Context()); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if !docker.unpaused {
		t.Fatal("resume did not unfreeze the container")
	}

	ioTr, ok := sc.transport.(*mcp.IOTransport)
	if !ok {
		t.Fatalf("transport = %T, want *mcp.IOTransport", sc.transport)
	}
	line, err := bufio.NewReader(ioTr.Reader).ReadString('\n')
	if err != nil {
		t.Fatalf("reading demuxed stdout: %v", err)
	}
	if line != `{"jsonrpc":"2.0","id":1,"result":{}}`+"\n" {
		t.Fatalf("stdout = %q", line)
	}

	if err := sc.cleanup(t.Context()); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if !docker.removed {
		t.Fatal("container was not removed during cleanup")
	}
}

func assertHardenedMCPHostConfig(t *testing.T, hostCfg *container.HostConfig) {
	t.Helper()
	if hostCfg == nil {
		t.Fatal("container host config is nil")
	}
	if !hostCfg.ReadonlyRootfs {
		t.Error("MCP backend root filesystem must be read-only")
	}
	if got := hostCfg.Tmpfs["/run/secrets"]; got == "" {
		t.Error("MCP backend must have a writable /run/secrets tmpfs")
	}
	if len(hostCfg.CapDrop) != 1 || hostCfg.CapDrop[0] != "ALL" {
		t.Errorf("CapDrop = %v, want [ALL]", hostCfg.CapDrop)
	}
}

// When the freezer is unavailable, dialStdioContainer proceeds unfrozen
// (degraded) rather than failing the backend, and resume is a no-op.
func TestDialStdioContainerDegradesWhenFreezeUnavailable(t *testing.T) {
	docker := &fakeDockerClient{pauseErr: errors.New("freezer cgroup controller not available")}
	sc, err := dialStdioContainer(t.Context(), Deps{Docker: docker, Logger: zaptest.NewLogger(t)}, "sift", &config.ContainerTool{
		Image:   "example/mcp:latest",
		Command: []string{"mcp-server"},
	}, "sessionabcdef", "ac-mcp-sessiona")
	if err != nil {
		t.Fatalf("dialStdioContainer should degrade, not fail: %v", err)
	}
	if docker.paused {
		t.Fatal("pause reported success despite the freezer error")
	}
	if err := sc.resume(t.Context()); err != nil {
		t.Fatalf("resume on an unfrozen container must be a no-op: %v", err)
	}
	if docker.unpaused {
		t.Fatal("resume unpaused a container that was never frozen")
	}
	_ = sc.cleanup(t.Context())
}

// dialHTTPContainer launches the backend on the bridge network (no stdin
// attach), freezes it for enforcement, and returns the bridge address/endpoint
// to connect to over Streamable HTTP.
func TestDialHTTPContainer(t *testing.T) {
	docker := &fakeDockerClient{}
	hc, err := dialHTTPContainer(t.Context(), Deps{Docker: docker, Logger: zaptest.NewLogger(t)}, "sift", &config.ContainerTool{
		Image:     "sift-gateway:demo",
		Transport: "http",
		Port:      4508,
		Path:      "/mcp",
	}, "sessionabcdef", "ac-mcp-sessiona")
	if err != nil {
		t.Fatalf("dialHTTPContainer: %v", err)
	}

	// HTTP backends connect over the network, not an attached stream.
	if docker.createdConfig.AttachStdin || docker.createdConfig.OpenStdin {
		t.Error("http backend must not attach stdin")
	}
	if !docker.started {
		t.Error("container was not started")
	}
	if !docker.paused {
		t.Error("container was not frozen before enforcement")
	}
	assertHardenedMCPHostConfig(t, docker.createdHostConfig)

	if want := "172.20.0.42:4508"; hc.address != want {
		t.Errorf("address = %q, want %q", hc.address, want)
	}
	if want := "http://172.20.0.42:4508/mcp"; hc.endpoint != want {
		t.Errorf("endpoint = %q, want %q", hc.endpoint, want)
	}

	if err := hc.resume(t.Context()); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if !docker.unpaused {
		t.Error("resume did not unpause the container")
	}
	_ = hc.cleanup(t.Context())
}

// An unset path defaults to "/".
func TestDialHTTPContainerDefaultPath(t *testing.T) {
	docker := &fakeDockerClient{}
	hc, err := dialHTTPContainer(t.Context(), Deps{Docker: docker, Logger: zaptest.NewLogger(t)}, "svc", &config.ContainerTool{
		Image: "x:1", Transport: "http", Port: 8080,
	}, "sessionabcdef", "ac-mcp-sessiona")
	if err != nil {
		t.Fatalf("dialHTTPContainer: %v", err)
	}
	if want := "http://172.20.0.42:8080/"; hc.endpoint != want {
		t.Errorf("endpoint = %q, want %q", hc.endpoint, want)
	}
	_ = hc.cleanup(t.Context())
}

// The audit enforcement marker must surface the posture gap from SPEC §14:
// container backends whose policy declares filesystem read/write allowlists
// get those allowlists confined at the proxy only (the kernel LSM runs in
// deny-list mode), and the audit trail must say so per tool call.
func TestBackendEnforcementMarker(t *testing.T) {
	tests := []struct {
		name string
		b    *Backend
		want string
	}{
		{"remote is proxy-only", &Backend{Kind: KindRemote}, "proxy-only"},
		{"container without policy is fully enforced", &Backend{Kind: KindStdio}, ""},
		{"container with deny-only filesystem policy is fully enforced", &Backend{
			Kind: KindStdio,
			Policy: &config.MCPServerPolicy{
				Filesystem: &config.FilesystemCaps{Deny: []string{"/etc/shadow"}},
			},
		}, ""},
		{"container with read allowlist marks fs-allowlists proxy-only", &Backend{
			Kind: KindStdio,
			Policy: &config.MCPServerPolicy{
				Filesystem: &config.FilesystemCaps{Read: []string{"/evidence"}},
			},
		}, "fs-allowlists:proxy-only"},
		{"container with write allowlist marks fs-allowlists proxy-only", &Backend{
			Kind: KindStdio,
			Policy: &config.MCPServerPolicy{
				Filesystem: &config.FilesystemCaps{Write: []string{"/cases"}},
			},
		}, "fs-allowlists:proxy-only"},
		{"component is unmarked", &Backend{
			Kind: KindComponent,
			Policy: &config.MCPServerPolicy{
				Filesystem: &config.FilesystemCaps{Read: []string{"/evidence"}},
			},
		}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.b.Enforcement(); got != tt.want {
				t.Errorf("Enforcement() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestNormalizeProgressToken guards the proxy against the go-sdk panic
// "progress token N is of type float64, not int or string". Claude Code sends a
// numeric progressToken (decoded as float64); without coercion SetProgressToken
// panics in the per-request goroutine and crashes the whole proxy on the first
// real tool call. Every normalized value must be safe to hand to the SDK.
func TestNormalizeProgressToken(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want any
	}{
		{"integral float64 -> int64", float64(2), int64(2)},
		{"zero float64 -> int64", float64(0), int64(0)},
		{"fractional float64 -> string", float64(2.5), "2.5"},
		{"int passthrough", 5, 5},
		{"int64 passthrough", int64(9), int64(9)},
		{"string passthrough", "tok-abc", "tok-abc"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := normalizeProgressToken(c.in)
			if got != c.want {
				t.Errorf("normalizeProgressToken(%v: %T) = %v: %T, want %v", c.in, c.in, got, got, c.want)
			}
			// The normalized token must never panic the SDK.
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("SetProgressToken panicked on normalized %v (%T): %v", got, got, r)
				}
			}()
			p := &mcp.CallToolParams{Name: "x"}
			p.SetProgressToken(got)
		})
	}
}
