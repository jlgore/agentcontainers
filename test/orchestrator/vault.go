package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// vaultClient mints and revokes lease-backed OpenRouter keys from the
// vault-openrouter-engine (github.com/jg/vault-openrouter-engine). It logs in
// with the pod's Kubernetes ServiceAccount JWT — no static token, no vault
// client-go, just the HTTP API. Budget is enforced server-side by the role's
// `limit`; revoking the lease deletes the upstream OpenRouter key.
type vaultClient struct {
	addr  string
	token string
	http  *http.Client
}

// newVaultClient authenticates to Vault via the kubernetes auth method using the
// worker SA token and the configured role, returning a ready client.
func newVaultClient(ctx context.Context, cfg Config) (*vaultClient, error) {
	jwt, err := os.ReadFile(saDir + "/token")
	if err != nil {
		return nil, fmt.Errorf("read sa token for vault login: %w", err)
	}
	vc := &vaultClient{
		addr: cfg.VaultAddr,
		http: &http.Client{Timeout: 20 * time.Second},
	}
	body, _ := json.Marshal(map[string]string{"role": cfg.VaultRole, "jwt": string(jwt)})
	path := fmt.Sprintf("/v1/auth/%s/login", cfg.VaultK8sMount)
	raw, code, err := vc.do(ctx, http.MethodPost, path, body, false)
	if err != nil {
		return nil, err
	}
	if code != 200 {
		return nil, fmt.Errorf("vault k8s login (role %s): http %d: %s", cfg.VaultRole, code, string(raw))
	}
	var out struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode vault login: %w", err)
	}
	if out.Auth.ClientToken == "" {
		return nil, fmt.Errorf("vault login returned no client_token")
	}
	vc.token = out.Auth.ClientToken
	return vc, nil
}

func (vc *vaultClient) do(ctx context.Context, method, path string, body []byte, auth bool) ([]byte, int, error) {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, vc.addr+path, r)
	if err != nil {
		return nil, 0, err
	}
	if auth {
		req.Header.Set("X-Vault-Token", vc.token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := vc.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return b, resp.StatusCode, nil
}

// mintedKey is a freshly issued, budget-capped, lease-backed OpenRouter key.
type mintedKey struct {
	APIKey  string
	LeaseID string
}

// MintKey reads openrouter/creds/<role>, creating a new budget-capped upstream
// key and returning it with its Vault lease id (for later revoke).
func (vc *vaultClient) MintKey(ctx context.Context, mount, role string) (*mintedKey, error) {
	path := fmt.Sprintf("/v1/%s/creds/%s", mount, role)
	raw, code, err := vc.do(ctx, http.MethodGet, path, nil, true)
	if err != nil {
		return nil, err
	}
	if code != 200 {
		return nil, fmt.Errorf("mint openrouter key (role %s): http %d: %s", role, code, string(raw))
	}
	var out struct {
		LeaseID string `json:"lease_id"`
		Data    struct {
			APIKey string `json:"api_key"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode creds: %w", err)
	}
	if out.Data.APIKey == "" {
		return nil, fmt.Errorf("creds response had no api_key")
	}
	return &mintedKey{APIKey: out.Data.APIKey, LeaseID: out.LeaseID}, nil
}

// RevokeLease revokes the key's lease, which deletes the upstream OpenRouter key.
// Best-effort: a revoke failure is logged by the caller, not fatal (the lease
// TTL is the backstop). Uses a fresh context so it still runs during teardown.
func (vc *vaultClient) RevokeLease(leaseID string) error {
	if leaseID == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	body, _ := json.Marshal(map[string]string{"lease_id": leaseID})
	raw, code, err := vc.do(ctx, http.MethodPut, "/v1/sys/leases/revoke", body, true)
	if err != nil {
		return err
	}
	if code != 204 && code != 200 {
		return fmt.Errorf("revoke lease: http %d: %s", code, string(raw))
	}
	return nil
}
