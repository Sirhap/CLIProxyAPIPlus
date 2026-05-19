package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

// WindsurfLanguageServerPool mirrors WindsurfAPI's src/langserver.js.
//
// The native implementation will keep one LS instance per effective proxy key,
// with a default no-proxy instance. Keeping this pool separate from the executor
// lets us port the original process/port/proxy lifecycle without entangling it
// with request translation code.
type WindsurfLanguageServerPool struct {
	cfg      *config.Config
	mu       sync.Mutex
	entries  map[string]*WindsurfLanguageServer
	nextPort int
}

type WindsurfLanguageServer struct {
	Key           string
	Port          int
	CSRFToken     string
	Process       *exec.Cmd
	StartedAt     time.Time
	LastUsedAt    time.Time
	Generation    string
	WorkspacePath string
	SessionID     string
	WarmedFor     string
	DataDir       string
	ProxyURL      string
}

func NewWindsurfLanguageServerPool(cfg *config.Config) *WindsurfLanguageServerPool {
	return &WindsurfLanguageServerPool{
		cfg:      cfg,
		entries:  make(map[string]*WindsurfLanguageServer),
		nextPort: windsurfDefaultPort + 1,
	}
}

func (p *WindsurfLanguageServerPool) Ensure(ctx context.Context, auth *cliproxyauth.Auth) (*WindsurfLanguageServer, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	settings := resolveWindsurfSettings(auth)
	if strings.TrimSpace(settings.LSBinaryPath) == "" {
		return nil, statusErr{code: 500, msg: "windsurf native transport requires ls_binary_path in auths/*.json or WINDSURF_LS_BINARY_PATH"}
	}
	if _, err := os.Stat(settings.LSBinaryPath); err != nil {
		return nil, statusErr{code: 500, msg: fmt.Sprintf("windsurf language server binary not found at %s", settings.LSBinaryPath)}
	}

	key := windsurfProxyKeyFor(p.cfg, auth)
	if existing := p.entries[key]; existing != nil {
		if windsurfIsPortOpen(existing.Port) {
			existing.LastUsedAt = time.Now()
			return existing, nil
		}
		p.stopLocked(existing)
		delete(p.entries, key)
	}

	p.evictIfNeededLocked(settings.MaxInstances, key)

	port, err := p.pickPortLocked(key)
	if err != nil {
		return nil, err
	}
	dataDir := filepath.Join(settings.LSDataDir, key)
	if errMkdir := os.MkdirAll(filepath.Join(dataDir, "db"), 0700); errMkdir != nil {
		return nil, fmt.Errorf("windsurf language server data dir: %w", errMkdir)
	}

	proxyURL := windsurfEffectiveProxyURL(p.cfg, auth)
	args := []string{
		"--api_server_url=" + settings.APIServerURL,
		fmt.Sprintf("--server_port=%d", port),
		"--csrf_token=" + windsurfDefaultCSRFToken,
		"--register_user_url=https://api.codeium.com/register_user/",
		"--codeium_dir=" + dataDir,
		"--database_dir=" + filepath.Join(dataDir, "db"),
		"--detect_proxy=false",
	}
	cmd := exec.Command(settings.LSBinaryPath, args...)
	cmd.Env = windsurfLanguageServerEnv(os.Environ(), proxyURL)
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	if errStart := cmd.Start(); errStart != nil {
		return nil, fmt.Errorf("windsurf language server start failed: %w", errStart)
	}

	entry := &WindsurfLanguageServer{
		Key:        key,
		Port:       port,
		CSRFToken:  windsurfDefaultCSRFToken,
		Process:    cmd,
		StartedAt:  time.Now(),
		LastUsedAt: time.Now(),
		Generation: uuid.NewString(),
		SessionID:  uuid.NewString(),
		DataDir:    dataDir,
		ProxyURL:   proxyURL,
	}
	p.entries[key] = entry
	go windsurfLogPipe("stdout", key, stdout)
	go windsurfLogPipe("stderr", key, stderr)
	go p.reapProcess(key, entry, cmd)

	if errWait := windsurfWaitPortReady(ctx, port, 25*time.Second); errWait != nil {
		p.stopLocked(entry)
		delete(p.entries, key)
		return nil, errWait
	}
	return entry, nil
}

func (p *WindsurfLanguageServerPool) stopLocked(entry *WindsurfLanguageServer) {
	if entry == nil || entry.Process == nil || entry.Process.Process == nil {
		return
	}
	closeWindsurfGRPCClient(entry.Port)
	_ = entry.Process.Process.Kill()
}

func (p *WindsurfLanguageServerPool) reapProcess(key string, entry *WindsurfLanguageServer, cmd *exec.Cmd) {
	err := cmd.Wait()
	p.mu.Lock()
	defer p.mu.Unlock()
	if current := p.entries[key]; current == entry {
		delete(p.entries, key)
		closeWindsurfGRPCClient(entry.Port)
	}
	if err != nil {
		log.Warnf("windsurf language server %s exited: %v", key, err)
	}
}

func (p *WindsurfLanguageServerPool) evictIfNeededLocked(maxInstances int, newKey string) {
	if maxInstances <= 0 || len(p.entries) < maxInstances {
		return
	}
	var evictKey string
	var evictAt time.Time
	for key, entry := range p.entries {
		if key == "default" || key == newKey {
			continue
		}
		if evictKey == "" || entry.LastUsedAt.Before(evictAt) {
			evictKey = key
			evictAt = entry.LastUsedAt
		}
	}
	if evictKey == "" {
		return
	}
	entry := p.entries[evictKey]
	p.stopLocked(entry)
	delete(p.entries, evictKey)
}

func (p *WindsurfLanguageServerPool) pickPortLocked(key string) (int, error) {
	if key == "default" && !windsurfIsPortOpen(windsurfDefaultPort) {
		return windsurfDefaultPort, nil
	}
	for attempts := 0; attempts < 100; attempts++ {
		port := p.nextPort
		p.nextPort++
		if !windsurfIsPortOpen(port) {
			return port, nil
		}
	}
	return 0, fmt.Errorf("windsurf language server: no free port near %d", windsurfDefaultPort)
}

func windsurfWaitPortReady(ctx context.Context, port int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return err
		}
		if windsurfIsPortOpen(port) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
	return fmt.Errorf("windsurf language server port %d not ready after %s", port, timeout)
}

func windsurfIsPortOpen(port int) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 250*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

var windsurfStickyProxyUserRE = regexp.MustCompile(`(?i)(?:[_-](?:sid|session|sessid|sticky|sess|token|res|rotating|ip[_-]?[0-9])|[+]ws_|^brd-customer-|^customer-|^user-|^res-|^sticky-|-zone-[a-z]+|-cc-[a-z]{2}|-country-|-state-|-city-|-session-|-sess-|-sticky-|-res-|-rotating-)`)

func windsurfProxyKey(auth *cliproxyauth.Auth) string {
	return windsurfProxyKeyFor(nil, auth)
}

func windsurfProxyKeyFor(cfg *config.Config, auth *cliproxyauth.Auth) string {
	proxy := windsurfEffectiveProxyURL(cfg, auth)
	if proxy == "" {
		return "default"
	}
	parsed, err := url.Parse(proxy)
	if err != nil || parsed.Hostname() == "" {
		sum := sha256.Sum256([]byte(proxy))
		return "px_" + hex.EncodeToString(sum[:6])
	}
	host := sanitizeWindsurfKey(parsed.Hostname())
	port := parsed.Port()
	if port == "" {
		port = "8080"
	}
	key := "px_" + host + "_" + sanitizeWindsurfKey(port)
	username := parsed.User.Username()
	segregate := false
	switch strings.TrimSpace(os.Getenv("WINDSURFAPI_LS_PER_PROXY_USER")) {
	case "1":
		segregate = username != ""
	case "0":
		segregate = false
	default:
		segregate = username != "" && windsurfStickyProxyUserRE.MatchString(username)
	}
	if segregate {
		safeUser := sanitizeWindsurfKey(username)
		if len(safeUser) > 32 {
			safeUser = safeUser[:32]
		}
		if safeUser != "" {
			key += "_u" + safeUser
		}
	}
	return key
}

func sanitizeWindsurfKey(value string) string {
	var b strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

func windsurfEffectiveProxyURL(cfg *config.Config, auth *cliproxyauth.Auth) string {
	proxyURL := ""
	if auth != nil {
		proxyURL = strings.TrimSpace(auth.ProxyURL)
	}
	if proxyURL == "" && cfg != nil {
		proxyURL = strings.TrimSpace(cfg.ProxyURL)
	}
	if strings.EqualFold(proxyURL, "direct") {
		return ""
	}
	return proxyURL
}

func windsurfLanguageServerEnv(source []string, proxyURL string) []string {
	allow := map[string]bool{
		"HOME": true, "PATH": true, "LANG": true, "LC_ALL": true,
		"TMPDIR": true, "TMP": true, "TEMP": true,
		"HTTP_PROXY": true, "HTTPS_PROXY": true, "NO_PROXY": true,
		"http_proxy": true, "https_proxy": true, "no_proxy": true,
		"SSL_CERT_FILE": true, "SSL_CERT_DIR": true, "NODE_EXTRA_CA_CERTS": true,
	}
	env := make([]string, 0, len(allow)+4)
	seen := map[string]bool{}
	for _, pair := range source {
		key, _, ok := strings.Cut(pair, "=")
		if !ok || !allow[key] {
			continue
		}
		env = append(env, pair)
		seen[key] = true
	}
	if !seen["HOME"] {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			env = append(env, "HOME="+home)
		}
	}
	if proxyURL != "" {
		env = appendWithoutKey(env, "HTTPS_PROXY="+proxyURL)
		env = appendWithoutKey(env, "HTTP_PROXY="+proxyURL)
		env = appendWithoutKey(env, "https_proxy="+proxyURL)
		env = appendWithoutKey(env, "http_proxy="+proxyURL)
	}
	return env
}

func appendWithoutKey(env []string, pair string) []string {
	key, _, _ := strings.Cut(pair, "=")
	out := env[:0]
	for _, existing := range env {
		existingKey, _, _ := strings.Cut(existing, "=")
		if existingKey != key {
			out = append(out, existing)
		}
	}
	return append(out, pair)
}

func windsurfLogPipe(kind, key string, r io.Reader) {
	if r == nil {
		return
	}
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			line := strings.TrimSpace(string(buf[:n]))
			if line != "" {
				if kind == "stderr" || strings.Contains(strings.ToLower(line), "error") {
					log.Warnf("[windsurf-ls:%s:%s] %s", key, kind, line)
				} else {
					log.Debugf("[windsurf-ls:%s:%s] %s", key, kind, line)
				}
			}
		}
		if err != nil {
			return
		}
	}
}

func windsurfWorkspacePath(root, apiKey string) string {
	sum := sha256.Sum256([]byte(apiKey))
	return filepath.Join(root, "workspace-"+hex.EncodeToString(sum[:8]))
}
