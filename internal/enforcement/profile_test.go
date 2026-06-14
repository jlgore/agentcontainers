package enforcement

import "testing"

func TestIsLoopbackEndpoint(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1:50051": true,
		"localhost:50051": true,
		"[::1]:50051":     true,
		":50051":          true,
		"10.0.0.5:50051":  false,
		"192.168.1.4:443": false,
		"example.com:443": false,
	}
	for addr, want := range cases {
		if got := isLoopbackEndpoint(addr); got != want {
			t.Errorf("isLoopbackEndpoint(%q) = %v, want %v", addr, got, want)
		}
	}
}

func TestOptionsFromProfile_TLSPolicy(t *testing.T) {
	caFile, certFile, keyFile := genTestCerts(t)

	t.Run("loopback plaintext allowed", func(t *testing.T) {
		_, err := optionsFromProfile(ConnectionProfile{Addr: "127.0.0.1:50051"}, nil)
		if err != nil {
			t.Fatalf("loopback plaintext should be allowed, got %v", err)
		}
	})

	t.Run("non-loopback plaintext rejected without opt-in", func(t *testing.T) {
		_, err := optionsFromProfile(ConnectionProfile{Addr: "10.0.0.5:50051"}, nil)
		if err == nil {
			t.Fatal("non-loopback plaintext without insecure-dev must be rejected")
		}
	})

	t.Run("non-loopback plaintext allowed with opt-in warns", func(t *testing.T) {
		warned := false
		_, err := optionsFromProfile(
			ConnectionProfile{Addr: "10.0.0.5:50051", InsecureDev: true},
			func(string) { warned = true },
		)
		if err != nil {
			t.Fatalf("insecure-dev opt-in should permit plaintext, got %v", err)
		}
		if !warned {
			t.Error("insecure-dev plaintext downgrade must log a warning")
		}
	})

	t.Run("mTLS material yields TLS, never downgrades", func(t *testing.T) {
		p := ConnectionProfile{
			Addr:           "10.0.0.5:50051", // non-loopback
			CACertPath:     caFile,
			ClientCertPath: certFile,
			ClientKeyPath:  keyFile,
		}
		opts, err := optionsFromProfile(p, nil)
		if err != nil {
			t.Fatalf("mTLS profile should build options, got %v", err)
		}
		cfg := defaultGRPCConfig()
		for _, opt := range opts {
			opt(cfg)
		}
		if cfg.insecure {
			t.Fatal("mTLS profile must not produce an insecure connection (silent downgrade)")
		}
		if cfg.tlsConfig == nil || len(cfg.tlsConfig.Certificates) == 0 {
			t.Fatal("mTLS profile must carry a client certificate")
		}
	})

	t.Run("bad cert path errors, never silently plaintext", func(t *testing.T) {
		p := ConnectionProfile{
			Addr:           "10.0.0.5:50051",
			CACertPath:     caFile,
			ClientCertPath: certFile + ".missing",
			ClientKeyPath:  keyFile,
		}
		if _, err := optionsFromProfile(p, nil); err == nil {
			t.Fatal("unreadable client cert must error, not fall back to plaintext")
		}
	})
}

func TestNewStrategyFromProfile_mTLS(t *testing.T) {
	caFile, certFile, keyFile := genTestCerts(t)
	s, err := NewStrategyFromProfile(ConnectionProfile{
		Addr:           "127.0.0.1:50051",
		CACertPath:     caFile,
		ClientCertPath: certFile,
		ClientKeyPath:  keyFile,
	}, nil)
	if err != nil {
		t.Fatalf("NewStrategyFromProfile mTLS: %v", err)
	}
	if s.Level() != LevelGRPC {
		t.Errorf("level = %v, want LevelGRPC", s.Level())
	}
	_ = s.Close()
}
