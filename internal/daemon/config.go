// Package daemon runs the capture-disabled stuV2 Messenger MCP fork.
package daemon

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

type Config struct {
	DataDir, Listen, Homeserver, UserID, Password      string
	BridgeURL, BridgeSecret, BridgeBot, InternalSecret string
	MCPToken                                           string
	UploadsDir, DownloadsDir                           string
	SyncEnabled, PairingEnabled, WritesEnabled         bool
}

func (c Config) BaseURL() string { return "http://" + c.Listen }
func DefaultDataDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "Application Support", "messenger-mcp-stuv2")
}

// privatePath refuses symlinks, other owners and group/world permissions.
// Existing data is never silently chmodded into apparent compliance.
func privatePath(path string, directory bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || info.IsDir() != directory || (!directory && !info.Mode().IsRegular()) {
		return errors.New("private data paths must be real directories or regular files, not symlinks")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("private directories require mode 700 and files mode 600")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) {
		return errors.New("private data must be owned by the current user")
	}
	return nil
}

func readEnv(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		out[strings.TrimSpace(k)] = v
	}
	return out, sc.Err()
}

func localEndpoint(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return false
	}
	return (u.Hostname() == "localhost" || isLoopbackIP(u.Hostname())) && u.Port() != ""
}

func (c Config) Validate() error {
	if len(c.MCPToken) < 32 || len(c.MCPToken) > 4096 || strings.ContainsAny(c.MCPToken, " \t\r\n") {
		return errors.New("MCP_TOKEN must be 32 to 4096 bytes without whitespace")
	}
	if c.MCPToken == c.InternalSecret || c.MCPToken == c.BridgeSecret || c.MCPToken == c.Password {
		return errors.New("MCP_TOKEN must be separate from pairing and provider secrets")
	}
	host, port, err := net.SplitHostPort(c.Listen)
	if err != nil || !isLoopbackIP(host) || port == "" {
		return errors.New("LISTEN must be a loopback IP and port")
	}
	if c.SyncEnabled || c.PairingEnabled || c.WritesEnabled {
		return errors.New("capture, pairing and writes are blocked pending a separately approved source privacy design")
	}
	if !localEndpoint(c.Homeserver) || !localEndpoint(c.BridgeURL) {
		return errors.New("Matrix and bridge endpoints must be explicit loopback HTTP URLs")
	}
	abs, err := filepath.Abs(c.DataDir)
	if err != nil || !filepath.IsAbs(c.DataDir) {
		return errors.New("data directory must be an absolute path")
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil || real != filepath.Clean(abs) {
		return errors.New("data directory must not contain symlink components")
	}
	return privatePath(c.DataDir, true)
}

func LoadConfig(dataDir string) (Config, error) {
	if err := privatePath(dataDir, true); err != nil {
		return Config{}, fmt.Errorf("data directory: %w", err)
	}
	path := filepath.Join(dataDir, "secrets.env")
	if err := privatePath(path, false); err != nil {
		return Config{}, errors.New("secrets file is missing or unsafe; require a private owned regular file with mode 600")
	}
	env, err := readEnv(path)
	if err != nil {
		return Config{}, errors.New("cannot read secrets configuration")
	}
	get := func(k, def string) string {
		if v := env[k]; v != "" {
			return v
		}
		return def
	}
	// Reject unknown/non-false enable values rather than accidentally enabling capture.
	for _, k := range []string{"SYNC_ENABLED", "PAIRING_ENABLED", "WRITES_ENABLED"} {
		if v := env[k]; v != "" && v != "false" {
			return Config{}, fmt.Errorf("%s must remain false; source capture is blocked", k)
		}
	}
	if v := env["READ_ONLY"]; v != "" && v != "true" {
		return Config{}, errors.New("READ_ONLY must remain true")
	}
	c := Config{DataDir: dataDir, Listen: get("LISTEN", "127.0.0.1:7381"), Homeserver: get("MATRIX_HOMESERVER", "http://127.0.0.1:7382"), UserID: get("MATRIX_USER_ID", "@operator:messenger.local"), Password: env["MATRIX_PASSWORD"], BridgeURL: get("BRIDGE_URL", "http://127.0.0.1:7383"), BridgeSecret: env["BRIDGE_PROVISIONING_SECRET"], BridgeBot: get("BRIDGE_BOT", "@metabot:messenger.local"), InternalSecret: env["INTERNAL_SECRET"], MCPToken: env["MCP_TOKEN"], UploadsDir: filepath.Join(dataDir, "uploads"), DownloadsDir: filepath.Join(dataDir, "downloads")}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}
