package management

import (
	"net"
	"net/http"
	"strconv"
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
