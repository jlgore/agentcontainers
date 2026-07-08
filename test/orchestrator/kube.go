package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

const saDir = "/var/run/secrets/kubernetes.io/serviceaccount"

// k8sClient talks to the in-cluster API server using the pod's ServiceAccount
// token + CA. Just enough to read a VMI's pod IP and issue a KubeVirt restart —
// deliberately no client-go, to keep the worker's dependency surface small.
type k8sClient struct {
	host  string
	token string
	http  *http.Client
}

func newK8sClient() (*k8sClient, error) {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := env("KUBERNETES_SERVICE_PORT", "443")
	if host == "" {
		return nil, fmt.Errorf("not running in-cluster (KUBERNETES_SERVICE_HOST unset); set GUEST_HOST to bypass")
	}
	token, err := os.ReadFile(saDir + "/token")
	if err != nil {
		return nil, fmt.Errorf("read sa token: %w", err)
	}
	caPEM, err := os.ReadFile(saDir + "/ca.crt")
	if err != nil {
		return nil, fmt.Errorf("read sa ca: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("parse sa ca")
	}
	return &k8sClient{
		host:  fmt.Sprintf("https://%s:%s", host, port),
		token: string(token),
		http: &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
		},
	}, nil
}

func (k *k8sClient) do(ctx context.Context, method, path string, body io.Reader) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, method, k.host+path, body)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+k.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := k.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return b, resp.StatusCode, nil
}

type vmi struct {
	Status struct {
		Phase      string `json:"phase"`
		Interfaces []struct {
			IPAddress string `json:"ipAddress"`
		} `json:"interfaces"`
		Conditions []struct {
			Type   string `json:"type"`
			Status string `json:"status"`
		} `json:"conditions"`
	} `json:"status"`
}

func (k *k8sClient) getVMI(ctx context.Context, ns, name string) (*vmi, error) {
	path := fmt.Sprintf("/apis/kubevirt.io/v1/namespaces/%s/virtualmachineinstances/%s", ns, name)
	b, code, err := k.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	if code != 200 {
		return nil, fmt.Errorf("get vmi %s/%s: http %d: %s", ns, name, code, string(b))
	}
	var v vmi
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, fmt.Errorf("decode vmi: %w", err)
	}
	return &v, nil
}

// vmiIP returns the first pod-network IP of the VMI (the address the worker
// SSHes to).
func (k *k8sClient) vmiIP(ctx context.Context, ns, name string) (string, error) {
	v, err := k.getVMI(ctx, ns, name)
	if err != nil {
		return "", err
	}
	for _, i := range v.Status.Interfaces {
		if i.IPAddress != "" {
			return i.IPAddress, nil
		}
	}
	return "", fmt.Errorf("vmi %s/%s has no interface IP yet (phase=%s)", ns, name, v.Status.Phase)
}

func (k *k8sClient) vmiReady(ctx context.Context, ns, name string) bool {
	v, err := k.getVMI(ctx, ns, name)
	if err != nil || v.Status.Phase != "Running" {
		return false
	}
	for _, c := range v.Status.Conditions {
		if c.Type == "Ready" {
			return c.Status == "True"
		}
	}
	return false
}

// podList is the trimmed core/v1 PodList shape the worker needs: each pod's
// name, IP, phase, deletion state, and Ready condition.
type podList struct {
	Items []struct {
		Metadata struct {
			Name              string `json:"name"`
			DeletionTimestamp string `json:"deletionTimestamp"`
		} `json:"metadata"`
		Status struct {
			Phase      string `json:"phase"`
			PodIP      string `json:"podIP"`
			Conditions []struct {
				Type   string `json:"type"`
				Status string `json:"status"`
			} `json:"conditions"`
		} `json:"status"`
	} `json:"items"`
}

func (k *k8sClient) listPods(ctx context.Context, ns, selector string) (*podList, error) {
	path := fmt.Sprintf("/api/v1/namespaces/%s/pods?labelSelector=%s", ns, url.QueryEscape(selector))
	b, code, err := k.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	if code != 200 {
		return nil, fmt.Errorf("list pods %s (%s): http %d: %s", ns, selector, code, string(b))
	}
	var pl podList
	if err := json.Unmarshal(b, &pl); err != nil {
		return nil, fmt.Errorf("decode pod list: %w", err)
	}
	return &pl, nil
}

// podIP returns the IP of a Running, Ready, non-terminating pod matching the
// selector (the address the worker SSHes to). A pod that is being deleted or not
// yet Ready is skipped, so a reset in flight is never picked up mid-recreate.
func (k *k8sClient) podIP(ctx context.Context, ns, selector string) (string, error) {
	pl, err := k.listPods(ctx, ns, selector)
	if err != nil {
		return "", err
	}
	for _, p := range pl.Items {
		if p.Metadata.DeletionTimestamp != "" || p.Status.Phase != "Running" || p.Status.PodIP == "" {
			continue
		}
		for _, c := range p.Status.Conditions {
			if c.Type == "Ready" && c.Status == "True" {
				return p.Status.PodIP, nil
			}
		}
	}
	return "", fmt.Errorf("no Running+Ready pod for %s/%s yet", ns, selector)
}

// deletePods deletes every pod matching the selector (the Deployment recreates
// them). Best-effort per pod; a NotFound is not an error.
func (k *k8sClient) deletePods(ctx context.Context, ns, selector string) error {
	pl, err := k.listPods(ctx, ns, selector)
	if err != nil {
		return err
	}
	for _, p := range pl.Items {
		if p.Metadata.DeletionTimestamp != "" {
			continue // already terminating
		}
		path := fmt.Sprintf("/api/v1/namespaces/%s/pods/%s", ns, p.Metadata.Name)
		b, code, err := k.do(ctx, http.MethodDelete, path, nil)
		if err != nil {
			return err
		}
		if code != 200 && code != 202 && code != 404 {
			return fmt.Errorf("delete pod %s/%s: http %d: %s", ns, p.Metadata.Name, code, string(b))
		}
	}
	return nil
}

// restartVM issues a KubeVirt restart subresource call on the VM.
func (k *k8sClient) restartVM(ctx context.Context, ns, name string) error {
	path := fmt.Sprintf("/apis/subresources.kubevirt.io/v1/namespaces/%s/virtualmachines/%s/restart", ns, name)
	b, code, err := k.do(ctx, http.MethodPut, path, nil)
	if err != nil {
		return err
	}
	if code != 202 && code != 200 {
		return fmt.Errorf("restart vm %s/%s: http %d: %s", ns, name, code, string(b))
	}
	return nil
}
