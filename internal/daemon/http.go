package daemon

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/0xjesus/messenger-mcp/internal/pair"
)

const pairTTL = 15 * time.Minute
const MaxHTTPBody = 64 << 10

// Authenticate every HTTP method before reading any body. Limit and pre-read
// even chunked bodies here, before mcp-go's unconditional body buffering.
func mcpBoundary(token string, next http.Handler) http.Handler {
	want := sha256.Sum256([]byte("Bearer " + token))
	slots := make(chan struct{}, 8)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		got := sha256.Sum256([]byte(r.Header.Get("Authorization")))
		if len(token) < 32 || len(r.Header.Values("Authorization")) != 1 || subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.ContentLength > MaxHTTPBody {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		}
		if r.Body != nil {
			body := http.MaxBytesReader(w, r.Body, MaxHTTPBody)
			b, err := io.ReadAll(body)
			_ = body.Close()
			if err != nil {
				http.Error(w, "request body exceeds limit or could not be read", http.StatusRequestEntityTooLarge)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(b))
			r.ContentLength = int64(len(b))
		}
		next.ServeHTTP(w, r)
	})
}

// loopbackOnly rejects requests whose Host is not a loopback name on our port,
// which blocks DNS-rebinding pages from reaching the service through a browser.
func loopbackOnly(port string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, p, err := net.SplitHostPort(r.Host)
		if err != nil || p != port || (host != "localhost" && !isLoopbackIP(host)) {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		if origins := r.Header.Values("Origin"); len(origins) > 0 {
			u, e := url.Parse(origins[0])
			if len(origins) != 1 || e != nil || u.Scheme != "http" || u.Host != r.Host || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
				http.Error(w, "forbidden origin", http.StatusForbidden)
				return
			}
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func isLoopbackIP(h string) bool {
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// pairTokenHandler mints a single-use /pair link for the CLI on this Mac.
func pairTokenHandler(secret, baseURL string, tokens *pair.Tokens) http.Handler {
	want := []byte("Bearer " + secret)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), want) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"url":        baseURL + "/pair?token=" + tokens.Issue(pairTTL),
			"expires_in": pairTTL.String(),
		})
	})
}
