package executor

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

const (
	windsurfProvider            = "windsurf"
	windsurfDefaultAPIURL       = "https://server.self-serve.windsurf.com"
	windsurfDefaultCSRFToken    = "windsurf-api-csrf-fixed-token"
	windsurfDefaultPort         = 42100
	windsurfDefaultMaxBodyBytes = 10 * 1024 * 1024
	windsurfDefaultLSMax        = 20
)

type windsurfSettings struct {
	Transport    string
	BaseURL      string
	APIKey       string
	AuthToken    string
	APIServerURL string
	LSBinaryPath string
	LSDataDir    string
	WorkspaceDir string
	MaxInstances int
}

func resolveWindsurfSettings(auth *cliproxyauth.Auth) windsurfSettings {
	settings := windsurfSettings{
		Transport:    strings.TrimSpace(os.Getenv("WINDSURF_TRANSPORT")),
		BaseURL:      strings.TrimSpace(os.Getenv("WINDSURF_BASE_URL")),
		APIKey:       strings.TrimSpace(os.Getenv("WINDSURF_API_KEY")),
		AuthToken:    strings.TrimSpace(os.Getenv("WINDSURF_AUTH_TOKEN")),
		APIServerURL: strings.TrimSpace(os.Getenv("WINDSURF_API_SERVER_URL")),
		LSBinaryPath: strings.TrimSpace(os.Getenv("WINDSURF_LS_BINARY_PATH")),
		LSDataDir:    strings.TrimSpace(os.Getenv("WINDSURF_LS_DATA_DIR")),
		WorkspaceDir: strings.TrimSpace(os.Getenv("WINDSURF_WORKSPACE_DIR")),
		MaxInstances: parsePositiveInt(os.Getenv("WINDSURF_LS_MAX_INSTANCES"), windsurfDefaultLSMax),
	}
	if settings.APIServerURL == "" {
		settings.APIServerURL = windsurfDefaultAPIURL
	}
	if settings.LSDataDir == "" {
		settings.LSDataDir = windsurfDefaultLSDataRoot()
	}
	if settings.WorkspaceDir == "" {
		settings.WorkspaceDir = filepath.Join(os.TempDir(), "windsurf-workspaces")
	}
	if auth == nil {
		return settings
	}
	if auth.Attributes != nil {
		settings.Transport = firstNonEmpty(auth.Attributes["transport"], settings.Transport)
		settings.BaseURL = firstNonEmpty(auth.Attributes["base_url"], settings.BaseURL)
		settings.APIKey = firstNonEmpty(auth.Attributes["api_key"], settings.APIKey)
		settings.AuthToken = firstNonEmpty(auth.Attributes["auth_token"], settings.AuthToken)
		settings.APIServerURL = firstNonEmpty(auth.Attributes["api_server_url"], settings.APIServerURL)
		settings.LSBinaryPath = firstNonEmpty(auth.Attributes["ls_binary_path"], settings.LSBinaryPath)
		settings.LSDataDir = firstNonEmpty(auth.Attributes["ls_data_dir"], settings.LSDataDir)
		settings.WorkspaceDir = firstNonEmpty(auth.Attributes["workspace_dir"], settings.WorkspaceDir)
		settings.MaxInstances = parsePositiveInt(auth.Attributes["ls_max_instances"], settings.MaxInstances)
	}
	return settings
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func parsePositiveInt(value string, fallback int) int {
	n, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}

func windsurfDefaultLSDataRoot() string {
	if runtime.GOOS == "darwin" {
		if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
			return filepath.Join(home, ".windsurf", "data")
		}
	}
	return "/opt/windsurf/data"
}

func windsurfCredential(settings windsurfSettings) string {
	return firstNonEmpty(settings.APIKey, settings.AuthToken)
}

func windsurfNormalizeModel(model string) string {
	model = strings.TrimSpace(model)
	model = strings.TrimPrefix(model, "windsurf/")
	if resolved := windsurfResolveModel(model); resolved != "" {
		return resolved
	}
	return model
}
