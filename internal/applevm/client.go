// Package applevm provides a client for ac-applevmd, a helper daemon that boots
// Linux microVMs via Apple's open-source containerization library and runs a
// private Docker daemon inside each one.
//
// ac-applevmd deliberately speaks the same wire contract as Docker Desktop's
// sandboxd, so this client returns the shared internal/sandbox types and
// satisfies the container.SandboxAPI interface. That lets the Apple backend
// reuse SandboxRuntime's VM-over-Docker lifecycle wholesale; only the transport
// endpoint (a different unix socket) and the runtime identity differ. See
// internal/container/applevm.go.
package applevm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"

	"go.uber.org/zap"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/sandbox"
)

// defaultSocketPath is the ac-applevmd unix socket path relative to $HOME.
const defaultSocketPath = ".agentcontainers/applevm/applevmd.sock"

// EnvSocketPath is the environment variable that overrides the ac-applevmd
// socket path.
const EnvSocketPath = "AC_APPLEVM_API"

// Client communicates with the ac-applevmd daemon via its Unix socket API.
type Client struct {
	httpClient *http.Client
	baseURL    string
	logger     *zap.Logger
}

// ClientOption configures a Client.
type ClientOption func(*clientOptions)

type clientOptions struct {
	socketPath string
	httpClient *http.Client
	logger     *zap.Logger
}

// WithSocketPath overrides the default ac-applevmd socket path.
func WithSocketPath(path string) ClientOption {
	return func(o *clientOptions) {
		o.socketPath = path
	}
}

// WithHTTPClient sets a custom HTTP client (useful for testing).
func WithHTTPClient(c *http.Client) ClientOption {
	return func(o *clientOptions) {
		o.httpClient = c
	}
}

// WithLogger sets the logger for the applevm client.
func WithLogger(l *zap.Logger) ClientOption {
	return func(o *clientOptions) {
		if l != nil {
			o.logger = l
		}
	}
}

// NewClient creates an applevm API client that communicates with the
// ac-applevmd daemon over its Unix socket. The socket path defaults to
// ~/.agentcontainers/applevm/applevmd.sock and can be overridden via the
// AC_APPLEVM_API environment variable or WithSocketPath.
func NewClient(opts ...ClientOption) (*Client, error) {
	o := &clientOptions{
		logger: zap.NewNop(),
	}
	for _, opt := range opts {
		opt(o)
	}

	if o.socketPath == "" {
		o.socketPath = os.Getenv(EnvSocketPath)
	}
	if o.socketPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("applevm client: get home dir: %w", err)
		}
		o.socketPath = filepath.Join(home, defaultSocketPath)
	}

	httpClient := o.httpClient
	if httpClient == nil {
		socketPath := o.socketPath
		httpClient = &http.Client{
			Transport: &http.Transport{
				DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
					return net.Dial("unix", socketPath)
				},
			},
		}
	}

	return &Client{
		httpClient: httpClient,
		baseURL:    "http://applevmd",
		logger:     o.logger,
	}, nil
}

// Health checks the daemon status.
func (c *Client) Health(ctx context.Context) (*sandbox.HealthResponse, error) {
	var h sandbox.HealthResponse
	if err := c.doGet(ctx, "/health", &h); err != nil {
		return nil, err
	}
	return &h, nil
}

// CreateVM creates and starts a new microVM.
func (c *Client) CreateVM(ctx context.Context, req *sandbox.VMCreateRequest) (*sandbox.VMCreateResponse, error) {
	var resp sandbox.VMCreateResponse
	if err := c.doPost(ctx, "/vm", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ListVMs returns all registered VMs.
func (c *Client) ListVMs(ctx context.Context) ([]sandbox.VMListEntry, error) {
	var vms []sandbox.VMListEntry
	if err := c.doGet(ctx, "/vm", &vms); err != nil {
		return nil, err
	}
	return vms, nil
}

// InspectVM returns details of a specific VM.
func (c *Client) InspectVM(ctx context.Context, name string) (*sandbox.VMInspectResponse, error) {
	var v sandbox.VMInspectResponse
	if err := c.doGet(ctx, "/vm/"+name, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

// StopVM stops a VM without removing it.
func (c *Client) StopVM(ctx context.Context, name string) error {
	return c.doPost(ctx, "/vm/"+name+"/stop", nil, nil)
}

// DeleteVM removes a VM and all its state.
func (c *Client) DeleteVM(ctx context.Context, name string) error {
	return c.doDelete(ctx, "/vm/"+name)
}

// Keepalive resets the idle timeout for a VM.
func (c *Client) Keepalive(ctx context.Context, name string) error {
	return c.doPost(ctx, "/vm/"+name+"/keepalive", nil, nil)
}

// UpdateProxyConfig updates the network proxy configuration for a running VM.
func (c *Client) UpdateProxyConfig(ctx context.Context, req *sandbox.ProxyConfigRequest) error {
	return c.doPost(ctx, "/network/proxyconfig", req, nil)
}

// --- internal HTTP helpers ---

func (c *Client) doGet(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return fmt.Errorf("applevm API %s: %w", path, err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("applevm API %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("applevm API GET %s: %s %s", path, resp.Status, body)
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return fmt.Errorf("applevm API GET %s: decode: %w", path, err)
		}
	}
	return nil
}

func (c *Client) doPost(ctx context.Context, path string, body any, out any) error {
	var r io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("applevm API %s: marshal: %w", path, err)
		}
		r = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, r)
	if err != nil {
		return fmt.Errorf("applevm API %s: %w", path, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("applevm API %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("applevm API POST %s: %s %s", path, resp.Status, b)
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return fmt.Errorf("applevm API POST %s: decode: %w", path, err)
		}
	}
	return nil
}

func (c *Client) doDelete(ctx context.Context, path string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+path, nil)
	if err != nil {
		return fmt.Errorf("applevm API %s: %w", path, err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("applevm API %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("applevm API DELETE %s: %s %s", path, resp.Status, b)
	}
	return nil
}
