package executor

import (
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestWindsurfExecutorIdentifier(t *testing.T) {
	exec := NewWindsurfExecutor(&config.Config{})
	if got := exec.Identifier(); got != "windsurf" {
		t.Fatalf("Identifier() = %q, want windsurf", got)
	}
}

func TestWindsurfUseNative(t *testing.T) {
	if windsurfUseNative(&cliproxyauth.Auth{Attributes: map[string]string{"transport": "sidecar"}}) {
		t.Fatal("sidecar transport must not use native transport")
	}
	if !windsurfUseNative(&cliproxyauth.Auth{}) {
		t.Fatal("empty transport should use native transport")
	}
	if !windsurfUseNative(&cliproxyauth.Auth{Attributes: map[string]string{"transport": "language-server"}}) {
		t.Fatal("language-server transport should use native transport")
	}
}

func TestWindsurfNormalizeModelStripsProviderPrefix(t *testing.T) {
	if got := windsurfNormalizeModel("windsurf/claude-sonnet-4.6"); got != "claude-sonnet-4.6" {
		t.Fatalf("normalize model = %q, want claude-sonnet-4.6", got)
	}
	if got := windsurfNormalizeModel("windsurf/gpt-5.2-medium"); got != "gpt-5.2" {
		t.Fatalf("normalize model alias = %q, want gpt-5.2", got)
	}
}
