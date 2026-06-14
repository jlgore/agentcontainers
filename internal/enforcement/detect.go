package enforcement

import (
	"context"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	healthgrpc "google.golang.org/grpc/health/grpc_health_v1"
)

// Level represents the enforcement mechanism in use, ordered from strongest
// to weakest.
type Level int

const (
	// LevelGRPC delegates enforcement to an agentcontainer-enforcer gRPC sidecar.
	LevelGRPC Level = iota

	// LevelNone indicates no enforcement mechanism is available.
	LevelNone
)

// String returns the string representation of the enforcement level.
func (l Level) String() string {
	switch l {
	case LevelGRPC:
		return "grpc"
	case LevelNone:
		return "none"
	default:
		return "unknown"
	}
}

// DetectLevel probes the system and returns the best available enforcement level.
func DetectLevel() Level {
	// Check for agentcontainer-enforcer sidecar via gRPC health check.
	if target := os.Getenv("AC_ENFORCER_ADDR"); target != "" {
		if ProbeEnforcerHealth(target) {
			return LevelGRPC
		}
	}

	return LevelNone
}

// ProbeEnforcerHealth checks if the agentcontainer-enforcer sidecar is reachable via gRPC.
// It returns true if the health check succeeds within a 2-second timeout. The
// connection is plaintext; use ProbeEnforcerHealthProfile to probe a mTLS
// endpoint with the same credentials a real client would present.
func ProbeEnforcerHealth(target string) bool {
	return probeEnforcerHealth(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
}

// ProbeEnforcerHealthProfile checks reachability using the profile's TLS
// configuration, so a managed mTLS-only enforcer (which rejects plaintext) is
// probed exactly as a normal client connects. It applies the same TLS policy as
// NewStrategyFromProfile: a non-loopback plaintext endpoint without an
// insecure-dev opt-in fails the probe.
func ProbeEnforcerHealthProfile(p ConnectionProfile) bool {
	opts, err := optionsFromProfile(p, nil)
	if err != nil {
		return false
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
		dialOpt = grpc.WithTransportCredentials(insecure.NewCredentials())
	}
	return probeEnforcerHealth(p.Addr, dialOpt)
}

// probeEnforcerHealth checks if the agentcontainer-enforcer sidecar is reachable
// via gRPC using the supplied transport credentials.
func probeEnforcerHealth(target string, creds grpc.DialOption) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := grpc.NewClient(target, creds)
	if err != nil {
		return false
	}
	defer conn.Close() //nolint:errcheck
	client := healthgrpc.NewHealthClient(conn)
	resp, err := client.Check(ctx, &healthgrpc.HealthCheckRequest{
		Service: "agentcontainers.enforcer.v1.Enforcer",
	})
	if err != nil {
		return false
	}
	return resp.GetStatus() == healthgrpc.HealthCheckResponse_SERVING
}

// NewStrategy creates a Strategy for the given enforcement level.
//
// When AC_ENFORCER_TLS_CERT, AC_ENFORCER_TLS_KEY, and AC_ENFORCER_TLS_CA are
// set, the gRPC connection uses mTLS. When only AC_ENFORCER_TLS_CA is set,
// server-only TLS verification is used. Otherwise insecure transport is used.
func NewStrategy(level Level) Strategy {
	switch level {
	case LevelGRPC:
		target := os.Getenv("AC_ENFORCER_ADDR")
		if target == "" {
			target = "127.0.0.1:50051"
		}
		opts, err := GRPCOptsFromEnv()
		if err != nil {
			return &FailClosedStrategy{}
		}
		s, err := NewGRPCStrategy(target, opts...)
		if err != nil {
			return &FailClosedStrategy{}
		}
		return s
	default:
		return &FailClosedStrategy{}
	}
}
