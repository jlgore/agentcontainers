package enforcement

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/enforcerapi"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/policy"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/secrets"
)

// GRPCStrategy delegates enforcement to an agentcontainer-enforcer gRPC sidecar service.
type GRPCStrategy struct {
	client   enforcerapi.EnforcerClient
	conn     *grpc.ClientConn
	level    Level
	events   map[string]chan Event
	cancelFn map[string]context.CancelFunc
	mu       sync.Mutex
}

// GRPCOption configures GRPCStrategy.
type GRPCOption func(*grpcConfig)

type grpcConfig struct {
	dialTimeout time.Duration
	tlsConfig   *tls.Config
	insecure    bool
}

func defaultGRPCConfig() *grpcConfig {
	return &grpcConfig{
		dialTimeout: 5 * time.Second,
		insecure:    true,
	}
}

// WithDialTimeout sets the gRPC dial timeout.
func WithDialTimeout(d time.Duration) GRPCOption {
	return func(c *grpcConfig) {
		c.dialTimeout = d
	}
}

// WithTLSConfig enables TLS with the given configuration.
func WithTLSConfig(tlsConf *tls.Config) GRPCOption {
	return func(c *grpcConfig) {
		c.tlsConfig = tlsConf
		c.insecure = false
	}
}

// WithInsecure explicitly enables insecure mode (no TLS).
func WithInsecure() GRPCOption {
	return func(c *grpcConfig) {
		c.insecure = true
		c.tlsConfig = nil
	}
}

// WithMTLSConfig builds a mutual-TLS configuration from PEM files and enables
// mTLS on the gRPC connection.
//
//   - certFile: path to the client certificate (PEM)
//   - keyFile:  path to the client private key (PEM)
//   - caFile:   path to the CA certificate used to verify the server (PEM)
//
// Returns an error if any file cannot be read or the certificate pool cannot
// be built.
func WithMTLSConfig(certFile, keyFile, caFile string) (GRPCOption, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("mtls: load client cert/key: %w", err)
	}

	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("mtls: read CA cert: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("mtls: failed to parse CA cert from %s", caFile)
	}

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS13,
	}

	return WithTLSConfig(tlsConf), nil
}

// tlsPoolFromPEM parses a PEM-encoded CA certificate into a cert pool.
func tlsPoolFromPEM(caPEM []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("failed to parse CA PEM")
	}
	return pool, nil
}

// GRPCOptsFromEnv derives GRPCOptions from the standard environment variables:
//
//	AC_ENFORCER_TLS_CERT / AC_ENFORCER_TLS_KEY / AC_ENFORCER_TLS_CA
//
// When all three are set, mTLS is configured. When only CA is set, server-only
// TLS is used. When none are set, insecure transport is used.
func GRPCOptsFromEnv() ([]GRPCOption, error) {
	certFile := os.Getenv("AC_ENFORCER_TLS_CERT")
	keyFile := os.Getenv("AC_ENFORCER_TLS_KEY")
	caFile := os.Getenv("AC_ENFORCER_TLS_CA")

	if certFile != "" && keyFile != "" && caFile != "" {
		opt, err := WithMTLSConfig(certFile, keyFile, caFile)
		if err != nil {
			return nil, err
		}
		return []GRPCOption{opt}, nil
	}

	if caFile != "" {
		caPEM, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read CA cert: %w", err)
		}
		pool, err := tlsPoolFromPEM(caPEM)
		if err != nil {
			return nil, err
		}
		tlsConf := &tls.Config{
			RootCAs:    pool,
			MinVersion: tls.VersionTLS13,
		}
		return []GRPCOption{WithTLSConfig(tlsConf)}, nil
	}

	return []GRPCOption{WithInsecure()}, nil
}

// ConnectionProfile is the complete set of information needed to reach an
// agentcontainer-enforcer endpoint and authenticate to it. It is threaded
// explicitly from sidecar startup into every enforcer client (runtime, MCP
// proxy, health probe), replacing the previous AC_ENFORCER_* process-global
// environment coupling.
type ConnectionProfile struct {
	// Addr is the gRPC endpoint, e.g. "127.0.0.1:50051".
	Addr string

	// CACertPath, ClientCertPath, and ClientKeyPath are PEM file paths for
	// mutual TLS. When all three are set the connection uses mTLS. When empty
	// the connection is plaintext, which is permitted only for a loopback Addr
	// unless InsecureDev is set.
	CACertPath     string
	ClientCertPath string
	ClientKeyPath  string

	// InsecureDev permits a plaintext connection to a non-loopback endpoint.
	// It is an explicit development-only opt-in; a prominent warning is logged
	// whenever it takes effect. Without it, a non-loopback endpoint with no
	// mTLS material is rejected rather than silently downgraded to plaintext.
	InsecureDev bool
}

// HasMTLS reports whether the profile carries a complete mTLS credential set.
func (p ConnectionProfile) HasMTLS() bool {
	return p.CACertPath != "" && p.ClientCertPath != "" && p.ClientKeyPath != ""
}

// isLoopbackEndpoint reports whether addr names a loopback host. A target with
// no host part (e.g. ":50051") is treated as loopback. Unix sockets, if ever
// passed, are also loopback.
func isLoopbackEndpoint(addr string) bool {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	if host == "" || host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// optionsFromProfile builds the gRPC dial options implied by a connection
// profile, enforcing the TLS policy:
//   - complete mTLS material → mutual TLS;
//   - loopback endpoint with no material → plaintext (host-local trust);
//   - non-loopback endpoint with no material → plaintext only with an explicit
//     InsecureDev opt-in (logged), otherwise an error.
//
// It never silently downgrades a TLS-credentialed profile to plaintext.
func optionsFromProfile(p ConnectionProfile, warn func(string)) ([]GRPCOption, error) {
	if p.HasMTLS() {
		opt, err := WithMTLSConfig(p.ClientCertPath, p.ClientKeyPath, p.CACertPath)
		if err != nil {
			return nil, err
		}
		return []GRPCOption{opt}, nil
	}
	if isLoopbackEndpoint(p.Addr) {
		return []GRPCOption{WithInsecure()}, nil
	}
	if p.InsecureDev {
		if warn != nil {
			warn(fmt.Sprintf("SECURITY: connecting to enforcer at %s over PLAINTEXT via insecure-dev opt-in — control-plane traffic, credentials, and policy are unauthenticated and unencrypted; do not use outside development", p.Addr))
		}
		return []GRPCOption{WithInsecure()}, nil
	}
	return nil, fmt.Errorf("enforcer endpoint %q is not loopback and no mTLS credentials were supplied; provide client cert/key/CA or set the enforcer insecure-dev opt-in", p.Addr)
}

// NewStrategyFromProfile builds a gRPC enforcement strategy for the given
// connection profile, applying the TLS policy in optionsFromProfile. Unlike
// NewStrategy it does not consult process-global environment variables. The
// optional warn callback receives a one-line message when an insecure-dev
// plaintext downgrade takes effect.
func NewStrategyFromProfile(p ConnectionProfile, warn func(string)) (*GRPCStrategy, error) {
	opts, err := optionsFromProfile(p, warn)
	if err != nil {
		return nil, err
	}
	return NewGRPCStrategy(p.Addr, opts...)
}

// DialEnforcer opens a raw gRPC client connection to an enforcer using the
// connection profile's TLS policy. It is for callers that need an
// enforcerapi.EnforcerClient (e.g. the MCP proxy) rather than a Strategy. The
// returned connection is the caller's to close. It never silently downgrades a
// credentialed profile to plaintext.
func DialEnforcer(p ConnectionProfile, warn func(string)) (*grpc.ClientConn, error) {
	opts, err := optionsFromProfile(p, warn)
	if err != nil {
		return nil, err
	}
	cfg := defaultGRPCConfig()
	for _, opt := range opts {
		opt(cfg)
	}
	var dialOpt grpc.DialOption
	switch {
	case cfg.insecure:
		dialOpt = grpc.WithTransportCredentials(insecure.NewCredentials())
	case cfg.tlsConfig != nil:
		dialOpt = grpc.WithTransportCredentials(credentials.NewTLS(cfg.tlsConfig))
	default:
		dialOpt = grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{}))
	}
	conn, err := grpc.NewClient(p.Addr, dialOpt)
	if err != nil {
		return nil, fmt.Errorf("dial enforcer %q: %w", p.Addr, err)
	}
	return conn, nil
}

// NewGRPCStrategy creates a gRPC-based enforcement strategy that connects
// to an agentcontainer-enforcer sidecar at the given target address.
func NewGRPCStrategy(target string, opts ...GRPCOption) (*GRPCStrategy, error) {
	cfg := defaultGRPCConfig()
	for _, opt := range opts {
		opt(cfg)
	}

	dialOpts := []grpc.DialOption{}
	if cfg.insecure {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else if cfg.tlsConfig != nil {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(cfg.tlsConfig)))
	} else {
		// Default: system TLS credentials
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{})))
	}

	conn, err := grpc.NewClient(target, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("grpc strategy: dial %q: %w", target, err)
	}

	client := enforcerapi.NewEnforcerClient(conn)

	return &GRPCStrategy{
		client:   client,
		conn:     conn,
		level:    LevelGRPC,
		events:   make(map[string]chan Event),
		cancelFn: make(map[string]context.CancelFunc),
	}, nil
}

// Apply registers the container and applies base policy followed by credential
// ACLs. Used by runtimes that do not inject secrets through the enforcer; the
// Docker path uses the split ApplyBasePolicy / InjectSecrets / ApplyCredentialACLs
// instead so ACLs are installed after the secret files exist.
func (s *GRPCStrategy) Apply(ctx context.Context, containerID string, initPID uint32, p *policy.ContainerPolicy) error {
	if err := s.ApplyBasePolicy(ctx, containerID, initPID, p); err != nil {
		return err
	}
	return s.ApplyCredentialACLs(ctx, containerID, p)
}

// ApplyBasePolicy registers the container and applies network, filesystem, and
// process policy — everything except credential ACLs.
func (s *GRPCStrategy) ApplyBasePolicy(ctx context.Context, containerID string, initPID uint32, p *policy.ContainerPolicy) error {
	// Resolve the cgroup path for this container.
	cgroupPath, err := ResolveCgroupPath(containerID)
	if err != nil {
		return fmt.Errorf("grpc strategy: resolve cgroup: %w", err)
	}

	// Register the container with the enforcer, passing init PID for
	// /proc/<pid>/root/ access during secret injection.
	_, err = s.client.RegisterContainer(ctx, &enforcerapi.RegisterContainerRequest{
		ContainerId: containerID,
		CgroupPath:  cgroupPath,
		InitPid:     initPID,
	})
	if err != nil {
		return fmt.Errorf("grpc strategy: register container: %w", err)
	}

	// Apply network policy.
	netReq := translateNetworkPolicy(containerID, p)
	netResp, err := s.client.ApplyNetworkPolicy(ctx, netReq)
	if err != nil {
		return fmt.Errorf("grpc strategy: apply network policy: %w", err)
	}
	if !netResp.GetSuccess() {
		return fmt.Errorf("grpc strategy: network policy failed: %s", netResp.GetError())
	}

	// Apply filesystem policy.
	fsReq := translateFilesystemPolicy(containerID, p)
	fsResp, err := s.client.ApplyFilesystemPolicy(ctx, fsReq)
	if err != nil {
		return fmt.Errorf("grpc strategy: apply filesystem policy: %w", err)
	}
	if !fsResp.GetSuccess() {
		return fmt.Errorf("grpc strategy: filesystem policy failed: %s", fsResp.GetError())
	}

	// Apply process policy.
	procReq := translateProcessPolicy(containerID, p)
	procResp, err := s.client.ApplyProcessPolicy(ctx, procReq)
	if err != nil {
		return fmt.Errorf("grpc strategy: apply process policy: %w", err)
	}
	if !procResp.GetSuccess() {
		return fmt.Errorf("grpc strategy: process policy failed: %s", procResp.GetError())
	}

	// Start event streaming for this container.
	// Non-fatal: a missing event stream degrades observability but does not
	// compromise enforcement. Log the error so operators can diagnose it.
	if err := s.startEventStream(containerID); err != nil {
		fmt.Printf("enforcement: event stream for container %s failed to start: %v\n", containerID, err)
	}

	return nil
}

// ApplyCredentialACLs installs the secret credential ACLs. Must be called after
// the secret files have been injected. A no-op when the policy declares no
// secret ACLs.
func (s *GRPCStrategy) ApplyCredentialACLs(ctx context.Context, containerID string, p *policy.ContainerPolicy) error {
	if len(p.SecretACLs) == 0 {
		return nil
	}
	credReq := translateCredentialPolicy(containerID, p)
	credResp, err := s.client.ApplyCredentialPolicy(ctx, credReq)
	if err != nil {
		return fmt.Errorf("grpc strategy: apply credential policy: %w", err)
	}
	if !credResp.GetSuccess() {
		return fmt.Errorf("grpc strategy: credential policy failed: %s", credResp.GetError())
	}
	return nil
}

// Update applies updated policies to an already-registered container.
func (s *GRPCStrategy) Update(ctx context.Context, containerID string, p *policy.ContainerPolicy) error {
	// Apply network policy.
	netReq := translateNetworkPolicy(containerID, p)
	netResp, err := s.client.ApplyNetworkPolicy(ctx, netReq)
	if err != nil {
		return fmt.Errorf("grpc strategy: update network policy: %w", err)
	}
	if !netResp.GetSuccess() {
		return fmt.Errorf("grpc strategy: network policy failed: %s", netResp.GetError())
	}

	// Apply filesystem policy.
	fsReq := translateFilesystemPolicy(containerID, p)
	fsResp, err := s.client.ApplyFilesystemPolicy(ctx, fsReq)
	if err != nil {
		return fmt.Errorf("grpc strategy: update filesystem policy: %w", err)
	}
	if !fsResp.GetSuccess() {
		return fmt.Errorf("grpc strategy: filesystem policy failed: %s", fsResp.GetError())
	}

	// Apply process policy.
	procReq := translateProcessPolicy(containerID, p)
	procResp, err := s.client.ApplyProcessPolicy(ctx, procReq)
	if err != nil {
		return fmt.Errorf("grpc strategy: update process policy: %w", err)
	}
	if !procResp.GetSuccess() {
		return fmt.Errorf("grpc strategy: process policy failed: %s", procResp.GetError())
	}

	// Apply credential policy (Phase 6).
	if len(p.SecretACLs) > 0 {
		credReq := translateCredentialPolicy(containerID, p)
		credResp, err := s.client.ApplyCredentialPolicy(ctx, credReq)
		if err != nil {
			return fmt.Errorf("grpc strategy: update credential policy: %w", err)
		}
		if !credResp.GetSuccess() {
			return fmt.Errorf("grpc strategy: credential policy failed: %s", credResp.GetError())
		}
	}

	return nil
}

// Remove unregisters the container from the enforcer sidecar.
func (s *GRPCStrategy) Remove(ctx context.Context, containerID string) error {
	// Stop event streaming if active.
	s.mu.Lock()
	if cancel, ok := s.cancelFn[containerID]; ok {
		cancel()
		delete(s.cancelFn, containerID)
	}
	if ch, ok := s.events[containerID]; ok {
		close(ch)
		delete(s.events, containerID)
	}
	s.mu.Unlock()

	// Unregister the container.
	_, err := s.client.UnregisterContainer(ctx, &enforcerapi.UnregisterContainerRequest{
		ContainerId: containerID,
	})
	if err != nil {
		return fmt.Errorf("grpc strategy: unregister container: %w", err)
	}

	return nil
}

// InjectSecrets writes secret values into the container via the enforcer sidecar.
// The enforcer writes directly to the container's filesystem through
// /proc/<init_pid>/root/run/secrets/<name>. BPF LSM SECRET_ACLS gates access.
func (s *GRPCStrategy) InjectSecrets(ctx context.Context, containerID string, resolved map[string]*secrets.Secret) error {
	entries := make([]*enforcerapi.SecretEntry, 0, len(resolved))
	for name, secret := range resolved {
		entries = append(entries, &enforcerapi.SecretEntry{
			Name:  name,
			Value: secret.Value,
			Mode:  0400,
		})
	}
	resp, err := s.client.InjectSecrets(ctx, &enforcerapi.InjectSecretsRequest{
		ContainerId: containerID,
		Secrets:     entries,
	})
	if err != nil {
		return fmt.Errorf("grpc strategy: inject secrets: %w", err)
	}
	if !resp.GetSuccess() {
		return fmt.Errorf("grpc strategy: inject secrets failed: %s", resp.GetError())
	}
	return nil
}

// Events returns the audit event channel for the given container.
func (s *GRPCStrategy) Events(containerID string) <-chan Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.events[containerID]
}

// Level returns LevelGRPC.
func (s *GRPCStrategy) Level() Level {
	return s.level
}

// Close closes the gRPC connection.
// The mutex is held for the full duration so that no concurrent Apply() call
// can observe a partially-closed connection.
func (s *GRPCStrategy) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Cancel all active event streams.
	for _, cancel := range s.cancelFn {
		cancel()
	}
	for _, ch := range s.events {
		close(ch)
	}
	s.cancelFn = make(map[string]context.CancelFunc)
	s.events = make(map[string]chan Event)

	return s.conn.Close()
}

// startEventStream starts a goroutine that streams events for the given container.
func (s *GRPCStrategy) startEventStream(containerID string) error {
	ctx, cancel := context.WithCancel(context.Background())

	stream, err := s.client.StreamEvents(ctx, &enforcerapi.StreamEventsRequest{
		ContainerId: containerID,
	})
	if err != nil {
		cancel()
		return fmt.Errorf("grpc strategy: start event stream: %w", err)
	}

	eventCh := make(chan Event, 100)

	s.mu.Lock()
	s.events[containerID] = eventCh
	s.cancelFn[containerID] = cancel
	s.mu.Unlock()

	go func() {
		defer cancel()
		for {
			protoEvent, err := stream.Recv()
			if err == io.EOF {
				return
			}
			if err != nil {
				// Stream closed or error
				return
			}

			event := translateEvent(protoEvent)
			select {
			case eventCh <- event:
			default:
				// Channel full, drop event
			}
		}
	}()

	return nil
}

// --- Policy translation helpers ---

func translateNetworkPolicy(containerID string, p *policy.ContainerPolicy) *enforcerapi.NetworkPolicyRequest {
	req := &enforcerapi.NetworkPolicyRequest{
		ContainerId:  containerID,
		AllowedHosts: p.AllowedHosts,
		DnsServers:   p.DNS,
	}

	for _, rule := range p.AllowedEgressRules {
		req.EgressRules = append(req.EgressRules, &enforcerapi.EgressRule{
			Host:     rule.Host,
			Port:     uint32(rule.Port),
			Protocol: rule.Protocol,
		})
	}

	return req
}

func translateFilesystemPolicy(containerID string, p *policy.ContainerPolicy) *enforcerapi.FilesystemPolicyRequest {
	req := &enforcerapi.FilesystemPolicyRequest{
		ContainerId: containerID,
	}

	for _, m := range p.AllowedMounts {
		if m.ReadOnly {
			req.ReadPaths = append(req.ReadPaths, m.Source)
		} else {
			req.WritePaths = append(req.WritePaths, m.Source)
		}
	}

	return req
}

func translateCredentialPolicy(containerID string, p *policy.ContainerPolicy) *enforcerapi.CredentialPolicyRequest {
	acls := make([]*enforcerapi.SecretAcl, len(p.SecretACLs))
	for i, acl := range p.SecretACLs {
		acls[i] = &enforcerapi.SecretAcl{
			Path:         acl.Path,
			AllowedTools: acl.AllowedTools,
			TtlSeconds:   acl.TTLSeconds,
		}
	}
	return &enforcerapi.CredentialPolicyRequest{
		ContainerId: containerID,
		SecretAcls:  acls,
	}
}

func translateProcessPolicy(containerID string, p *policy.ContainerPolicy) *enforcerapi.ProcessPolicyRequest {
	return &enforcerapi.ProcessPolicyRequest{
		ContainerId:     containerID,
		AllowedBinaries: p.AllowedCommands,
	}
}

// translateEvent converts a gRPC EnforcementEvent to an Event.
func translateEvent(protoEvent *enforcerapi.EnforcementEvent) Event {
	event := Event{
		Timestamp: protoEvent.GetTimestampNs(),
		PID:       protoEvent.GetPid(),
		Comm:      protoEvent.GetComm(),
	}

	// Map verdict
	switch protoEvent.GetVerdict() {
	case "allow":
		event.Verdict = VerdictAllow
	case "block":
		event.Verdict = VerdictBlock
	default:
		event.Verdict = VerdictBlock
	}

	// Map domain-specific event type and details
	details := protoEvent.GetDetails()
	switch protoEvent.GetDomain() {
	case "network":
		event.Type = EventNetConnect
		event.Net = &NetEvent{}
		// Parse details map for IP, port, protocol if needed
	case "filesystem":
		event.Type = EventFSOpen
		event.FS = &FSEvent{
			Path: details["path"],
		}
	case "process":
		event.Type = EventExec
		event.Exec = &ExecEvent{
			Binary: details["binary"],
		}
	case "credential":
		event.Type = EventCred
	}

	return event
}

// Compile-time interface check.
var _ Strategy = (*GRPCStrategy)(nil)
