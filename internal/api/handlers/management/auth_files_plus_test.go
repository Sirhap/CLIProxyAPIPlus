package management

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

func TestStartKiroAuthCodeCallbackForwarderFallsBackWhenPreferredPortBusy(t *testing.T) {
	busyListener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("listen busy port: %v", err)
	}
	defer busyListener.Close()

	preferredPort := busyListener.Addr().(*net.TCPAddr).Port
	targetBase := "http://127.0.0.1:18319/v0/management/kiro/callback"

	forwarder, actualPort, err := startKiroAuthCodeCallbackForwarder(preferredPort, targetBase)
	if err != nil {
		t.Fatalf("start fallback forwarder: %v", err)
	}
	defer stopCallbackForwarderInstance(actualPort, forwarder)

	if actualPort == preferredPort {
		t.Fatalf("actual port = preferred busy port %d, want fallback port", preferredPort)
	}

	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get("http://127.0.0.1:" + strconv.Itoa(actualPort) + "/oauth/callback?code=abc&state=xyz")
	if err != nil {
		t.Fatalf("request fallback forwarder: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusFound)
	}
	if got, want := resp.Header.Get("Location"), targetBase+"?code=abc&state=xyz"; got != want {
		t.Fatalf("location = %q, want %q", got, want)
	}
}

func TestBuildKiroPortalURL(t *testing.T) {
	raw := buildKiroPortalURL("http://localhost:3128", "state-123", "challenge-123")
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}
	if got, want := parsed.Scheme+"://"+parsed.Host+parsed.Path, "https://app.kiro.dev/signin"; got != want {
		t.Fatalf("portal URL = %q, want %q", got, want)
	}
	q := parsed.Query()
	if got, want := q.Get("state"), "state-123"; got != want {
		t.Fatalf("state = %q, want %q", got, want)
	}
	if got, want := q.Get("redirect_uri"), "http://localhost:3128"; got != want {
		t.Fatalf("redirect_uri = %q, want %q", got, want)
	}
	if got, want := q.Get("redirect_from"), "KiroIDE"; got != want {
		t.Fatalf("redirect_from = %q, want %q", got, want)
	}
}

func TestStartKiroPortalCallbackServerUsesNextPortAndCapturesCallback(t *testing.T) {
	busyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen busy port: %v", err)
	}
	defer busyListener.Close()

	nextListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve fallback port: %v", err)
	}
	fallbackPort := nextListener.Addr().(*net.TCPAddr).Port
	nextListener.Close()

	busyPort := busyListener.Addr().(*net.TCPAddr).Port
	server, redirectURI, callbacks, err := startKiroPortalCallbackServer("state-123", []int{busyPort, fallbackPort})
	if err != nil {
		t.Fatalf("start portal callback server: %v", err)
	}
	defer server.Close()

	if got, want := redirectURI, "http://localhost:"+strconv.Itoa(fallbackPort); got != want {
		t.Fatalf("redirect URI = %q, want %q", got, want)
	}

	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get("http://127.0.0.1:" + strconv.Itoa(fallbackPort) + "/signin/callback?login_option=google&code=abc&state=state-123")
	if err != nil {
		t.Fatalf("request callback server: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusFound)
	}
	if got := resp.Header.Get("Location"); !strings.Contains(got, "auth_status=success") {
		t.Fatalf("location = %q, want success redirect", got)
	}

	select {
	case callback := <-callbacks:
		if callback.Path != "/signin/callback" || callback.LoginOption != "google" || callback.Code != "abc" || callback.State != "state-123" {
			t.Fatalf("unexpected callback: %#v", callback)
		}
	default:
		t.Fatal("expected callback result")
	}
}

func TestExchangeKiroPortalSocialToken(t *testing.T) {
	var gotPayload map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Method, http.MethodPost; got != want {
			t.Fatalf("method = %q, want %q", got, want)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}
		if err := json.Unmarshal(body, &gotPayload); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"accessToken":"access","refreshToken":"refresh","profileArn":"arn:test","expiresIn":3600}`))
	}))
	defer srv.Close()

	resp, err := exchangeKiroPortalSocialToken(context.Background(), srv.Client(), srv.URL, "code-1", "verifier-1", "http://localhost:3128/signin/callback?login_option=google")
	if err != nil {
		t.Fatalf("exchange token: %v", err)
	}
	if resp.AccessToken != "access" || resp.RefreshToken != "refresh" || resp.ProfileArn != "arn:test" || resp.ExpiresIn != 3600 {
		t.Fatalf("unexpected token response: %#v", resp)
	}
	if got, want := gotPayload["redirect_uri"], "http://localhost:3128/signin/callback?login_option=google"; got != want {
		t.Fatalf("redirect_uri = %q, want %q", got, want)
	}
}
