package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/0xjesus/messenger-mcp/internal/ledger"
	"github.com/0xjesus/messenger-mcp/internal/outbox"
	"github.com/0xjesus/messenger-mcp/internal/tools"
	"github.com/mark3labs/mcp-go/server"
)

const Version = "0.2.0-stuv2-cold"
const Identity = "stuV2/messenger-mcp"

// coldHandler deliberately constructs no Matrix or bridge client. Configuration
// cannot unlock source capture in this release. Liveness is not source readiness.
func coldHandler(cfg Config) (http.Handler, func(), error) {
	if err := cfg.Validate(); err != nil {
		return nil, nil, err
	}
	for _, name := range []string{"ledger.db", "ledger.db-wal", "ledger.db-shm"} {
		p := filepath.Join(cfg.DataDir, name)
		if _, err := os.Lstat(p); err == nil {
			if err := privatePath(p, false); err != nil {
				return nil, nil, err
			}
		} else if !os.IsNotExist(err) {
			return nil, nil, err
		}
	}
	dbPath := filepath.Join(cfg.DataDir, "ledger.db")
	f, err := os.OpenFile(dbPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err == nil {
		_ = f.Close()
	} else if !os.IsExist(err) {
		return nil, nil, err
	}
	l, err := ledger.Open(dbPath)
	if err != nil {
		return nil, nil, err
	}
	closeLedger := func() { _ = l.Close() }
	q, err := outbox.New(l, nil, outbox.Config{})
	if err != nil {
		closeLedger()
		return nil, nil, err
	}
	s := server.NewMCPServer(Identity, Version, server.WithToolCapabilities(true))
	tools.Register(s, tools.Deps{L: l, Q: q, Status: func(context.Context) map[string]any {
		return map[string]any{"identity": Identity, "version": Version, "state": "unpaired", "capture": "capture_disabled", "sync_enabled": false, "pairing_enabled": false, "read_only": true, "source_ready": false, "coverage": "not_synced", "matrix": "not_started", "messenger": "unpaired", "action": "Source capture is blocked pending separate privacy approval. No account is connected by this service."}
	}})
	mux := http.NewServeMux()
	mux.Handle("/mcp", mcpBoundary(cfg.MCPToken, server.NewStreamableHTTPServer(s)))
	disabled := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "pairing and source capture are disabled", http.StatusForbidden)
	})
	mux.Handle("/pair", disabled)
	mux.Handle("/pair/", disabled)
	mux.Handle("/internal/pair-token", disabled)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{\"alive\":true,\"source_ready\":false,\"capture\":\"capture_disabled\"}\n"))
	})
	_, port, _ := net.SplitHostPort(cfg.Listen)
	return loopbackOnly(port, mux), closeLedger, nil
}

// Run serves a cold read-only ledger. No sync, provider polling, pairing, queue
// worker or replay goroutine is started, including for an existing ledger.
func Run(ctx context.Context, cfg Config, log *slog.Logger) error {
	h, closeLedger, err := coldHandler(cfg)
	if err != nil {
		return err
	}
	defer closeLedger()
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = srv.Shutdown(c)
		case <-done:
		}
	}()
	log.Info("stuV2 messenger-mcp listening; unpaired, capture disabled", "addr", cfg.Listen, "version", Version)
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
