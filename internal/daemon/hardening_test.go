package daemon

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0xjesus/messenger-mcp/internal/ledger"
	"github.com/0xjesus/messenger-mcp/internal/outbox"
)

const testToken = "synthetic-token-never-a-real-secret-123456789"

func coldConfig(t *testing.T) Config {
	t.Helper()
	d := t.TempDir()
	if err := os.Chmod(d, 0700); err != nil {
		t.Fatal(err)
	}
	return Config{DataDir: d, Listen: "127.0.0.1:7381", MCPToken: testToken, Homeserver: "http://127.0.0.1:7382", BridgeURL: "http://127.0.0.1:7383"}
}

type unreadBody struct{ reads int }

func (b *unreadBody) Read(p []byte) (int, error) { b.reads++; return 0, io.EOF }
func (b *unreadBody) Close() error               { return nil }

func TestMCPBoundaryBeforeSDKBuffering(t *testing.T) {
	for _, method := range []string{"POST", "GET", "DELETE", "OPTIONS"} {
		for _, auth := range []string{"", "Bearer wrong", "Bearer pair-secret"} {
			t.Run(method+auth, func(t *testing.T) {
				called := false
				h := loopbackOnly("7381", mcpBoundary(testToken, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })))
				r := httptest.NewRequest(method, "http://127.0.0.1:7381/mcp", nil)
				body := &unreadBody{}
				r.Body = body
				r.ContentLength = MaxHTTPBody + 1
				if auth != "" {
					r.Header.Set("Authorization", auth)
				}
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				if w.Code != 401 || called || body.reads != 0 {
					t.Fatalf("code=%d called=%v reads=%d", w.Code, called, body.reads)
				}
			})
		}
	}
	for _, tc := range []struct {
		name, host, origin string
		size               int
		chunked            bool
		want               int
	}{
		{"good", "127.0.0.1:7381", "", 8, false, 204},
		{"same-origin", "127.0.0.1:7381", "http://127.0.0.1:7381", 8, false, 204},
		{"host", "evil.test:7381", "", 8, false, 403},
		{"origin", "127.0.0.1:7381", "http://evil.test", 8, false, 403},
		{"null-origin", "127.0.0.1:7381", "null", 8, false, 403},
		{"other-port", "127.0.0.1:7381", "http://127.0.0.1:80", 8, false, 403},
		{"oversize", "127.0.0.1:7381", "", MaxHTTPBody + 1, false, 413},
		{"chunked-oversize", "127.0.0.1:7381", "", MaxHTTPBody + 1, true, 413},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			h := loopbackOnly("7381", mcpBoundary(testToken, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true; w.WriteHeader(204) })))
			r := httptest.NewRequest("POST", "http://"+tc.host+"/mcp", strings.NewReader(strings.Repeat("x", tc.size)))
			if tc.chunked {
				r.ContentLength = -1
			}
			r.Header.Set("Authorization", "Bearer "+testToken)
			if tc.origin != "" {
				r.Header.Set("Origin", tc.origin)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.want || called != (tc.want == 204) {
				t.Fatalf("code=%d called=%v", w.Code, called)
			}
		})
	}
}

func TestColdConfigNoProviderSecretsAndFailClosed(t *testing.T) {
	cfg := coldConfig(t)
	writeSecrets(t, cfg.DataDir, "MCP_TOKEN="+testToken+"\nREAD_ONLY=true\nSYNC_ENABLED=false\nPAIRING_ENABLED=false\n", 0600)
	got, err := LoadConfig(cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	if got.Password != "" || got.BridgeSecret != "" || got.InternalSecret != "" || got.SyncEnabled || got.PairingEnabled {
		t.Fatal("cold config requires no provider credentials")
	}
	for _, extra := range []string{"SYNC_ENABLED=true", "SYNC_ENABLED=1", "PAIRING_ENABLED=true", "WRITES_ENABLED=true", "READ_ONLY=false", "MATRIX_HOMESERVER=https://example.test:443", "BRIDGE_URL=http://example.test:80", "INTERNAL_SECRET=" + testToken, "MCP_TOKEN=short"} {
		writeSecrets(t, cfg.DataDir, "MCP_TOKEN="+testToken+"\n"+extra+"\n", 0600)
		if _, err := LoadConfig(cfg.DataDir); err == nil {
			t.Fatalf("must refuse %s", strings.Split(extra, "=")[0])
		}
	}
	for _, enable := range []func(*Config){func(c *Config) { c.SyncEnabled = true }, func(c *Config) { c.PairingEnabled = true }, func(c *Config) { c.WritesEnabled = true }} {
		c := cfg
		enable(&c)
		if c.Validate() == nil {
			t.Fatal("direct config must not unlock capture")
		}
	}
}

func TestPrivateDataModesAndSymlinks(t *testing.T) {
	cfg := coldConfig(t)
	writeSecrets(t, cfg.DataDir, "MCP_TOKEN="+testToken+"\n", 0600)
	if err := os.Chmod(cfg.DataDir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(cfg.DataDir); err == nil {
		t.Fatal("permissive root accepted")
	}
	_ = os.Chmod(cfg.DataDir, 0700)
	p := filepath.Join(cfg.DataDir, "secrets.env")
	target := filepath.Join(cfg.DataDir, "target")
	if err := os.Rename(p, target); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, p); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(cfg.DataDir); err == nil {
		t.Fatal("symlink secret accepted")
	}
	_ = os.Remove(p)
	writeSecrets(t, cfg.DataDir, "MCP_TOKEN="+testToken+"\n", 0600)
	if err := os.Symlink(target, filepath.Join(cfg.DataDir, "ledger.db")); err != nil {
		t.Fatal(err)
	}
	if _, closeFn, err := coldHandler(cfg); err == nil {
		closeFn()
		t.Fatal("symlink ledger accepted")
	}
}

// Actual HTTP SDK transport, not just direct HandleMessage. All providers are
// synthetic loopback traps and the ledger contains synthetic fixtures only.
func TestColdHTTPTransportNoProviderContactsOrReplay(t *testing.T) {
	var contacts atomic.Int64
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contacts.Add(1)
		http.Error(w, "must never contact provider", 500)
	}))
	defer provider.Close()
	cfg := coldConfig(t)
	cfg.Homeserver = provider.URL
	cfg.BridgeURL = provider.URL
	// Existing queued work is retained without transmission or status mutation.
	p := filepath.Join(cfg.DataDir, "ledger.db")
	if err := os.WriteFile(p, nil, 0600); err != nil {
		t.Fatal(err)
	}
	l, err := ledger.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.UpsertChat(context.Background(), ledger.Chat{ChatID: "c", RoomID: "!synthetic:local", Name: "Synthetic"}); err != nil {
		t.Fatal(err)
	}
	q, err := outbox.New(l, nil, outbox.Config{WritesEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	job, err := q.Enqueue(context.Background(), outbox.Job{ChatID: "c", Kind: outbox.KindText, Text: "synthetic queued text"})
	if err != nil {
		t.Fatal(err)
	}
	_ = l.Close()
	// Exercise Run, including its entire startup and shutdown goroutine path.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Listen = probe.Addr().String()
	_ = probe.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil))) }()
	defer func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(6 * time.Second):
			t.Error("shutdown timed out")
		}
	}()
	client := &http.Client{Timeout: 3 * time.Second}
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, e := client.Get(cfg.BaseURL() + "/healthz")
		if e == nil {
			_ = resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(e)
		}
		time.Sleep(10 * time.Millisecond)
	}
	do := func(method, path, body, token, session string) (int, http.Header, string) {
		t.Helper()
		r, e := http.NewRequest(method, cfg.BaseURL()+path, strings.NewReader(body))
		if e != nil {
			t.Fatal(e)
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		if session != "" {
			r.Header.Set("Mcp-Session-Id", session)
		}
		resp, e := client.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer resp.Body.Close()
		b, e := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if e != nil {
			t.Fatal(e)
		}
		return resp.StatusCode, resp.Header, string(b)
	}
	for _, m := range []string{"POST", "GET", "DELETE"} {
		for _, token := range []string{"", "wrong-synthetic-token"} {
			code, _, _ := do(m, "/mcp", "{}", token, "")
			if code != 401 {
				t.Fatalf("unauth %s %d", m, code)
			}
		}
	}
	if code, _, _ := do("POST", "/mcp", strings.Repeat("x", MaxHTTPBody+1), testToken, ""); code != 413 {
		t.Fatalf("wire oversized body=%d", code)
	}
	badOrigin, _ := http.NewRequest("POST", cfg.BaseURL()+"/mcp", strings.NewReader("{}"))
	badOrigin.Header.Set("Origin", "http://untrusted.synthetic")
	badOrigin.Header.Set("Authorization", "Bearer "+testToken)
	originResp, err := client.Do(badOrigin)
	if err != nil {
		t.Fatal(err)
	}
	_ = originResp.Body.Close()
	if originResp.StatusCode != 403 {
		t.Fatalf("wire cross-origin=%d", originResp.StatusCode)
	}
	code, headers, body := do("POST", "/mcp", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"synthetic","version":"1"}}}`, testToken, "")
	if code != 200 || !strings.Contains(body, Identity) {
		t.Fatalf("initialize %d %s", code, body)
	}
	session := headers.Get("Mcp-Session-Id")
	request := func(method string, params any) string {
		b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 2, "method": method, "params": params})
		code, _, body := do("POST", "/mcp", string(b), testToken, session)
		if code != 200 {
			t.Fatalf("rpc %s code=%d body=%s", method, code, body)
		}
		return body
	}
	body = request("tools/list", map[string]any{})
	if !strings.Contains(body, "get_status") || !strings.Contains(body, "list_chats") || strings.Contains(body, "send_message") || strings.Contains(body, "get_messages") {
		t.Fatalf("unsafe tools %s", body)
	}
	body = request("tools/call", map[string]any{"name": "get_status", "arguments": map[string]any{}})
	for _, s := range []string{"unpaired", "capture_disabled", "not_synced", "not_started"} {
		if !strings.Contains(body, s) {
			t.Fatalf("missing %s: %s", s, body)
		}
	}
	for _, name := range []string{"send_message", "send_file", "mark_read", "cancel_outbox", "get_messages", "download_attachment"} {
		body = request("tools/call", map[string]any{"name": name, "arguments": map[string]any{"chat_id": "c", "text": "no"}})
		if !strings.Contains(body, "error") && !strings.Contains(body, "isError") {
			t.Fatalf("blocked tool returned success: %s", body)
		}
	}
	for _, path := range []string{"/pair", "/pair/start", "/internal/pair-token"} {
		code, _, _ := do("POST", path, "{}", testToken, session)
		if code != 403 {
			t.Fatalf("pair path %s=%d", path, code)
		}
	}
	time.Sleep(1100 * time.Millisecond) // catches an erroneously started queue worker
	if contacts.Load() != 0 {
		t.Fatalf("provider contacts=%d", contacts.Load())
	}
	l, err = ledger.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	q, err = outbox.New(l, nil, outbox.Config{})
	if err != nil {
		t.Fatal(err)
	}
	v, err := q.Get(context.Background(), job.JobID)
	if err != nil || v.Status != outbox.StatusQueued || v.Attempts != 0 {
		t.Fatalf("replayed queued job: %+v %v", v, err)
	}
}
