package mcpproxy

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"github.com/moby/moby/api/pkg/stdcopy"
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
