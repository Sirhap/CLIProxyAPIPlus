package management

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestRequestWindsurfToken_Auth1SavesNativeAuthRecord(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	gin.SetMode(gin.TestMode)
	resetWindsurfLoginTestState(t)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/check":
			_ = json.NewEncoder(w).Encode(map[string]any{"userExists": true, "hasPassword": true})
		case "/password-login":
			if got := r.Header.Get("Origin"); got != "https://windsurf.com" {
				t.Fatalf("Origin = %q, want https://windsurf.com", got)
			}
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode password login body: %v", err)
			}
			if body["email"] != "windsurf@example.com" || body["password"] != "secret" {
				t.Fatalf("password login body = %#v", body)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"token": "auth1-token"})
		case "/post-auth":
			if got := r.Header.Get("X-Devin-Auth1-Token"); got != "auth1-token" {
				t.Fatalf("X-Devin-Auth1-Token = %q, want auth1-token", got)
			}
			if got := r.Header.Get("Content-Type"); got != "application/proto" {
				t.Fatalf("Content-Type = %q, want application/proto", got)
			}
			w.Header().Set("Content-Type", "application/proto")
			_, _ = w.Write([]byte("devin-session-token$abc123 account-deadbeef org-feedface"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	windsurfCheckLoginMethodURL = upstream.URL + "/check"
	windsurfAuth1PasswordLoginURL = upstream.URL + "/password-login"
	windsurfPostAuthURLNew = upstream.URL + "/post-auth"
	windsurfPostAuthURLLegacy = upstream.URL + "/post-auth-legacy"

	store := &memoryAuthStore{}
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir()}, coreauth.NewManager(nil, nil, nil))
	h.tokenStore = store

	body := `{
		"email":"windsurf@example.com",
		"password":"secret",
		"proxy_url":"direct",
		"ls_binary_path":"/opt/windsurf/language_server_linux_x64",
		"ls_data_dir":"/tmp/windsurf-data",
		"workspace_dir":"/tmp/windsurf-workspaces",
		"ls_max_instances":2,
		"priority":7,
		"excluded_models":["swe-1.6-fast"]
	}`
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/v0/management/windsurf-auth-url", strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")

	h.RequestWindsurfToken(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d with body %s", http.StatusOK, rec.Code, rec.Body.String())
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.items) != 1 {
		t.Fatalf("expected 1 saved auth record, got %d", len(store.items))
	}
	saved := store.items["windsurf-windsurf@example.com.json"]
	if saved == nil {
		t.Fatalf("expected windsurf auth record to be saved, got %#v", store.items)
	}
	if saved.Provider != "windsurf" {
		t.Fatalf("provider = %q, want windsurf", saved.Provider)
	}
	if saved.ProxyURL != "direct" {
		t.Fatalf("proxy_url = %q, want direct", saved.ProxyURL)
	}
	if got := saved.Metadata["type"]; got != "windsurf" {
		t.Fatalf("metadata.type = %#v, want windsurf", got)
	}
	if got := saved.Metadata["api_key"]; got != "devin-session-token$abc123" {
		t.Fatalf("metadata.api_key = %#v, want session token", got)
	}
	if got := saved.Metadata["transport"]; got != "native" {
		t.Fatalf("metadata.transport = %#v, want native", got)
	}
	if got := saved.Metadata["session_token"]; got != "devin-session-token$abc123" {
		t.Fatalf("metadata.session_token = %#v, want session token", got)
	}
	if got := saved.Metadata["account_id"]; got != "account-deadbeef" {
		t.Fatalf("metadata.account_id = %#v, want account-deadbeef", got)
	}
	if got := saved.Metadata["auth_method"]; got != "auth1" {
		t.Fatalf("metadata.auth_method = %#v, want auth1", got)
	}
	if got := saved.Metadata["ls_binary_path"]; got != "/opt/windsurf/language_server_linux_x64" {
		t.Fatalf("metadata.ls_binary_path = %#v", got)
	}
	if got := saved.Metadata["ls_max_instances"]; got != "2" {
		t.Fatalf("metadata.ls_max_instances = %#v, want 2", got)
	}
	if got := saved.Metadata["priority"]; got != 7 {
		t.Fatalf("metadata.priority = %#v, want 7", got)
	}
}

func TestRequestWindsurfToken_FirebaseFallbackRegistersAndSavesAuth(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	gin.SetMode(gin.TestMode)
	resetWindsurfLoginTestState(t)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/check":
			_ = json.NewEncoder(w).Encode(map[string]any{"userExists": false, "hasPassword": false})
		case "/connections":
			_ = json.NewEncoder(w).Encode(map[string]any{})
		case "/firebase":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"idToken":      "firebase-id-token",
				"refreshToken": "firebase-refresh-token",
			})
		case "/register":
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode register body: %v", err)
			}
			if body["firebase_id_token"] != "firebase-id-token" {
				t.Fatalf("firebase_id_token = %q", body["firebase_id_token"])
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"api_key":        "sk-ws-01-test",
				"name":           "Windsurf User",
				"api_server_url": "https://server.self-serve.windsurf.com",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	windsurfCheckLoginMethodURL = upstream.URL + "/check"
	windsurfAuth1ConnectionsURL = upstream.URL + "/connections"
	windsurfFirebaseAuthURL = upstream.URL + "/firebase"
	windsurfRegisterURLs = []windsurfEndpoint{{URL: upstream.URL + "/register", Label: "new"}}

	store := &memoryAuthStore{}
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir()}, coreauth.NewManager(nil, nil, nil))
	h.tokenStore = store

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/v0/management/windsurf-login", strings.NewReader(`{"email":"firebase@example.com","password":"secret"}`))
	ctx.Request.Header.Set("Content-Type", "application/json")

	h.RequestWindsurfToken(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d with body %s", http.StatusOK, rec.Code, rec.Body.String())
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	saved := store.items["windsurf-firebase@example.com.json"]
	if saved == nil {
		t.Fatalf("expected saved auth record, got %#v", store.items)
	}
	if got := saved.Metadata["api_key"]; got != "sk-ws-01-test" {
		t.Fatalf("metadata.api_key = %#v, want sk-ws-01-test", got)
	}
	if got := saved.Metadata["auth_token"]; got != "firebase-id-token" {
		t.Fatalf("metadata.auth_token = %#v, want firebase-id-token", got)
	}
	if got := saved.Metadata["refresh_token"]; got != "firebase-refresh-token" {
		t.Fatalf("metadata.refresh_token = %#v, want firebase-refresh-token", got)
	}
	if got := saved.Metadata["auth_method"]; got != "firebase" {
		t.Fatalf("metadata.auth_method = %#v, want firebase", got)
	}
	if got := saved.Metadata["api_server_url"]; got != "https://server.self-serve.windsurf.com" {
		t.Fatalf("metadata.api_server_url = %#v", got)
	}
}

func resetWindsurfLoginTestState(t *testing.T) {
	t.Helper()
	oldFirebaseAuthURL := windsurfFirebaseAuthURL
	oldAuth1ConnectionsURL := windsurfAuth1ConnectionsURL
	oldAuth1PasswordLoginURL := windsurfAuth1PasswordLoginURL
	oldCheckLoginMethodURL := windsurfCheckLoginMethodURL
	oldPostAuthURLNew := windsurfPostAuthURLNew
	oldPostAuthURLLegacy := windsurfPostAuthURLLegacy
	oldRegisterURLs := append([]windsurfEndpoint(nil), windsurfRegisterURLs...)
	windsurfLoginFailures.Lock()
	windsurfLoginFailures.items = make(map[string]*windsurfEmailFailure)
	windsurfLoginFailures.Unlock()
	t.Cleanup(func() {
		windsurfFirebaseAuthURL = oldFirebaseAuthURL
		windsurfAuth1ConnectionsURL = oldAuth1ConnectionsURL
		windsurfAuth1PasswordLoginURL = oldAuth1PasswordLoginURL
		windsurfCheckLoginMethodURL = oldCheckLoginMethodURL
		windsurfPostAuthURLNew = oldPostAuthURLNew
		windsurfPostAuthURLLegacy = oldPostAuthURLLegacy
		windsurfRegisterURLs = oldRegisterURLs
		windsurfLoginFailures.Lock()
		windsurfLoginFailures.items = make(map[string]*windsurfEmailFailure)
		windsurfLoginFailures.Unlock()
	})
}
