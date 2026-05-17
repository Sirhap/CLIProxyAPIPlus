package management

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	codebuddyauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/codebuddy"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/auth/codex"
	kiroauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/kiro"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v7/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

const (
	codexDeviceUserCodeURL              = "https://auth.openai.com/api/accounts/deviceauth/usercode"
	codexDeviceTokenURL                 = "https://auth.openai.com/api/accounts/deviceauth/token"
	codexDeviceVerificationURL          = "https://auth.openai.com/codex/device"
	codexDeviceTokenExchangeRedirectURI = "https://auth.openai.com/deviceauth/callback"
	codexDeviceTimeout                  = 15 * time.Minute
	kiroPortalAuthBaseURL               = "https://app.kiro.dev"
	kiroPortalTokenURL                  = "https://prod.us-east-1.auth.desktop.kiro.dev/oauth/token"
	kiroPortalTimeout                   = 10 * time.Minute
	kiroAuthCodeCallbackPort            = 19877
)

var kiroPortalCallbackPorts = []int{3128, 4649, 6588, 8008, 9091, 49153, 50153, 51153, 52153, 53153}

type codexDeviceUserCodeRequest struct {
	ClientID string `json:"client_id"`
}

type codexDeviceUserCodeResponse struct {
	DeviceAuthID string          `json:"device_auth_id"`
	UserCode     string          `json:"user_code"`
	UserCodeAlt  string          `json:"usercode"`
	Interval     json.RawMessage `json:"interval"`
}

type codexDeviceTokenRequest struct {
	DeviceAuthID string `json:"device_auth_id"`
	UserCode     string `json:"user_code"`
}

type codexDeviceTokenResponse struct {
	AuthorizationCode string `json:"authorization_code"`
	CodeVerifier      string `json:"code_verifier"`
	CodeChallenge     string `json:"code_challenge"`
}

type kiroPortalCallbackResult struct {
	Path             string
	LoginOption      string
	Code             string
	State            string
	Error            string
	ErrorDescription string
}

type kiroPortalTokenRequest struct {
	Code         string `json:"code"`
	CodeVerifier string `json:"code_verifier"`
	RedirectURI  string `json:"redirect_uri"`
}

type kiroPortalTokenResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	ProfileArn   string `json:"profileArn"`
	ExpiresIn    int    `json:"expiresIn"`
}

type kiroPortalCallbackServer struct {
	port     int
	server   *http.Server
	listener net.Listener
	done     chan struct{}
}

func (h *Handler) RequestCodexDeviceToken(c *gin.Context) {
	ctx := PopulateAuthContext(context.Background(), c)

	fmt.Println("Initializing Codex device authentication...")

	httpClient := util.SetProxy(&h.cfg.SDKConfig, &http.Client{})
	userCodeResp, err := requestCodexDeviceUserCode(ctx, httpClient)
	if err != nil {
		log.Errorf("Failed to request Codex device code: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to request device code"})
		return
	}

	deviceCode := strings.TrimSpace(userCodeResp.UserCode)
	if deviceCode == "" {
		deviceCode = strings.TrimSpace(userCodeResp.UserCodeAlt)
	}
	deviceAuthID := strings.TrimSpace(userCodeResp.DeviceAuthID)
	if deviceCode == "" || deviceAuthID == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "device flow response missing required fields"})
		return
	}

	state := fmt.Sprintf("codex-device-%d", time.Now().UnixNano())
	RegisterOAuthSession(state, "codex")
	SetOAuthSessionError(state, "device_code|"+codexDeviceVerificationURL+"|"+deviceCode)

	pollInterval := parseCodexDevicePollInterval(userCodeResp.Interval)

	go func() {
		tokenResp, errPoll := pollCodexDeviceToken(ctx, httpClient, deviceAuthID, deviceCode, pollInterval)
		if errPoll != nil {
			SetOAuthSessionError(state, oauthSessionErrorWithCause("Authentication failed", errPoll))
			log.Errorf("Codex device authentication failed: %v", errPoll)
			return
		}

		authCode := strings.TrimSpace(tokenResp.AuthorizationCode)
		codeVerifier := strings.TrimSpace(tokenResp.CodeVerifier)
		codeChallenge := strings.TrimSpace(tokenResp.CodeChallenge)
		if authCode == "" || codeVerifier == "" || codeChallenge == "" {
			SetOAuthSessionError(state, "Device flow response missing required fields")
			return
		}

		openaiAuth := codex.NewCodexAuth(h.cfg)
		bundle, errExchange := openaiAuth.ExchangeCodeForTokensWithRedirect(
			ctx,
			authCode,
			codexDeviceTokenExchangeRedirectURI,
			&codex.PKCECodes{
				CodeVerifier:  codeVerifier,
				CodeChallenge: codeChallenge,
			},
		)
		if errExchange != nil {
			SetOAuthSessionError(state, oauthSessionErrorWithCause("Failed to exchange authorization code for tokens", errExchange))
			log.Errorf("Failed to exchange Codex device code for tokens: %v", errExchange)
			return
		}

		claims, _ := codex.ParseJWTToken(bundle.TokenData.IDToken)
		planType := ""
		hashAccountID := ""
		if claims != nil {
			planType = strings.TrimSpace(claims.CodexAuthInfo.ChatgptPlanType)
			if accountID := claims.GetAccountID(); accountID != "" {
				digest := sha256.Sum256([]byte(accountID))
				hashAccountID = hex.EncodeToString(digest[:])[:8]
			}
		}

		tokenStorage := openaiAuth.CreateTokenStorage(bundle)
		fileName := codex.CredentialFileName(tokenStorage.Email, planType, hashAccountID, true)
		record := &coreauth.Auth{
			ID:       fileName,
			Provider: "codex",
			FileName: fileName,
			Storage:  tokenStorage,
			Metadata: map[string]any{
				"email":            tokenStorage.Email,
				"account_id":       tokenStorage.AccountID,
				"codex_login_mode": "device",
			},
		}
		savedPath, errSave := h.saveTokenRecord(ctx, record)
		if errSave != nil {
			SetOAuthSessionError(state, "Failed to save authentication tokens")
			log.Errorf("Failed to save Codex device authentication tokens: %v", errSave)
			return
		}

		fmt.Printf("Codex device authentication successful! Token saved to %s\n", savedPath)
		CompleteOAuthSession(state)
		CompleteOAuthSessionsByProvider("codex")
	}()

	c.JSON(http.StatusOK, gin.H{
		"status":           "ok",
		"state":            state,
		"method":           "device_code",
		"url":              codexDeviceVerificationURL,
		"user_code":        deviceCode,
		"verification_uri": codexDeviceVerificationURL,
	})
}

func requestCodexDeviceUserCode(ctx context.Context, client *http.Client) (*codexDeviceUserCodeResponse, error) {
	body, err := json.Marshal(codexDeviceUserCodeRequest{ClientID: codex.ClientID})
	if err != nil {
		return nil, fmt.Errorf("failed to encode codex device request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, codexDeviceUserCodeURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create codex device request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to request codex device code: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read codex device code response: %w", err)
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		trimmed := strings.TrimSpace(string(respBody))
		if trimmed == "" {
			trimmed = "empty response body"
		}
		return nil, fmt.Errorf("codex device code request failed with status %d: %s", resp.StatusCode, trimmed)
	}

	var parsed codexDeviceUserCodeResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return nil, fmt.Errorf("failed to decode codex device code response: %w", err)
	}

	return &parsed, nil
}

func pollCodexDeviceToken(ctx context.Context, client *http.Client, deviceAuthID, userCode string, interval time.Duration) (*codexDeviceTokenResponse, error) {
	deadline := time.Now().Add(codexDeviceTimeout)

	for {
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("codex device authentication timed out after 15 minutes")
		}

		body, err := json.Marshal(codexDeviceTokenRequest{
			DeviceAuthID: deviceAuthID,
			UserCode:     userCode,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to encode codex device poll request: %w", err)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, codexDeviceTokenURL, bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("failed to create codex device poll request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to poll codex device token: %w", err)
		}

		respBody, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil {
			return nil, fmt.Errorf("failed to read codex device poll response: %w", readErr)
		}

		switch {
		case resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices:
			var parsed codexDeviceTokenResponse
			if err := json.Unmarshal(respBody, &parsed); err != nil {
				return nil, fmt.Errorf("failed to decode codex device token response: %w", err)
			}
			return &parsed, nil
		case resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound:
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(interval):
				continue
			}
		default:
			trimmed := strings.TrimSpace(string(respBody))
			if trimmed == "" {
				trimmed = "empty response body"
			}
			return nil, fmt.Errorf("codex device token polling failed with status %d: %s", resp.StatusCode, trimmed)
		}
	}
}

func parseCodexDevicePollInterval(raw json.RawMessage) time.Duration {
	defaultInterval := 5 * time.Second
	if len(raw) == 0 {
		return defaultInterval
	}

	var asString string
	if err := json.Unmarshal(raw, &asString); err == nil {
		if seconds, convErr := strconv.Atoi(strings.TrimSpace(asString)); convErr == nil && seconds > 0 {
			return time.Duration(seconds) * time.Second
		}
	}

	var asInt int
	if err := json.Unmarshal(raw, &asInt); err == nil && asInt > 0 {
		return time.Duration(asInt) * time.Second
	}

	return defaultInterval
}

func (h *Handler) RequestKiroPortalToken(c *gin.Context) {
	state, errState := generateKiroPortalState()
	if errState != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate state"})
		return
	}

	codeVerifier, codeChallenge, errPKCE := generateKiroPKCE()
	if errPKCE != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate pkce"})
		return
	}

	server, redirectURI, callbacks, errServer := startKiroPortalCallbackServer(state, kiroPortalCallbackPorts)
	if errServer != nil {
		log.WithError(errServer).Error("failed to start kiro portal callback server")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to start callback server"})
		return
	}

	RegisterOAuthSession(state, "kiro")
	authURL := buildKiroPortalURL(redirectURI, state, codeChallenge)
	SetOAuthSessionError(state, "auth_url|"+authURL)

	go func() {
		defer server.Close()

		select {
		case callback := <-callbacks:
			if callback.Error != "" {
				SetOAuthSessionError(state, firstNonEmpty(callback.ErrorDescription, callback.Error))
				return
			}
			if callback.State != state {
				SetOAuthSessionError(state, "invalid state")
				return
			}
			if callback.LoginOption != "google" && callback.LoginOption != "github" {
				SetOAuthSessionError(state, "unsupported portal login option: "+callback.LoginOption)
				return
			}
			if strings.TrimSpace(callback.Code) == "" {
				SetOAuthSessionError(state, "missing authorization code")
				return
			}

			fullRedirectURI := redirectURI + callback.Path + "?login_option=" + url.QueryEscape(callback.LoginOption)
			tokenResp, errToken := exchangeKiroPortalSocialToken(context.Background(), h.portalHTTPClient(), kiroPortalTokenURL, callback.Code, codeVerifier, fullRedirectURI)
			if errToken != nil {
				log.WithError(errToken).Error("failed to exchange kiro portal authorization code")
				SetOAuthSessionError(state, oauthSessionErrorWithCause("failed to exchange portal token", errToken))
				return
			}

			provider := "Google"
			if callback.LoginOption == "github" {
				provider = "Github"
			}
			expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
			tokenData := &kiroauth.KiroTokenData{
				AccessToken:  tokenResp.AccessToken,
				RefreshToken: tokenResp.RefreshToken,
				ProfileArn:   tokenResp.ProfileArn,
				ExpiresAt:    expiresAt.Format(time.RFC3339),
				AuthMethod:   "social",
				Provider:     provider,
			}

			savedPath, errSave := h.saveKiroTokenDataRecord(context.Background(), tokenData)
			if errSave != nil {
				log.WithError(errSave).Error("failed to save kiro portal token")
				SetOAuthSessionError(state, "failed to save portal token")
				return
			}

			fmt.Printf("Kiro portal authentication successful! Token saved to %s\n", savedPath)
			CompleteOAuthSession(state)
			CompleteOAuthSessionsByProvider("kiro")
		case <-time.After(kiroPortalTimeout):
			SetOAuthSessionError(state, "Authorization timed out")
		}
	}()

	c.JSON(http.StatusOK, gin.H{
		"status": "ok",
		"state":  state,
		"method": "portal",
		"url":    authURL,
	})
}

func generateKiroPortalState() (string, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func buildKiroPortalURL(redirectURI, state, codeChallenge string) string {
	params := url.Values{}
	params.Set("state", state)
	params.Set("code_challenge", codeChallenge)
	params.Set("code_challenge_method", "S256")
	params.Set("redirect_uri", redirectURI)
	params.Set("redirect_from", "KiroIDE")
	return kiroPortalAuthBaseURL + "/signin?" + params.Encode()
}

func startKiroPortalCallbackServer(expectedState string, ports []int) (*kiroPortalCallbackServer, string, <-chan kiroPortalCallbackResult, error) {
	var listener net.Listener
	var errListen error
	for _, port := range ports {
		listener, errListen = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if errListen == nil {
			break
		}
	}
	if listener == nil {
		return nil, "", nil, fmt.Errorf("failed to listen on portal callback ports: %w", errListen)
	}

	actualPort := listener.Addr().(*net.TCPAddr).Port
	redirectURI := fmt.Sprintf("http://localhost:%d", actualPort)
	results := make(chan kiroPortalCallbackResult, 1)

	mux := http.NewServeMux()
	handleCallback := func(w http.ResponseWriter, r *http.Request) {
		result := kiroPortalCallbackResult{
			Path:             r.URL.Path,
			LoginOption:      strings.TrimSpace(r.URL.Query().Get("login_option")),
			Code:             strings.TrimSpace(r.URL.Query().Get("code")),
			State:            strings.TrimSpace(r.URL.Query().Get("state")),
			Error:            strings.TrimSpace(r.URL.Query().Get("error")),
			ErrorDescription: strings.TrimSpace(r.URL.Query().Get("error_description")),
		}
		if result.State != expectedState {
			result.Error = "invalid_state"
		}
		select {
		case results <- result:
		default:
		}
		target := kiroPortalAuthBaseURL + "/signin?auth_status=success&redirect_from=KiroIDE"
		if result.Error != "" {
			target = kiroPortalAuthBaseURL + "/signin?auth_status=error&redirect_from=KiroIDE&error_message=" + url.QueryEscape(firstNonEmpty(result.ErrorDescription, result.Error))
		}
		http.Redirect(w, r, target, http.StatusFound)
	}
	mux.HandleFunc("/oauth/callback", handleCallback)
	mux.HandleFunc("/signin/callback", handleCallback)

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	done := make(chan struct{})
	go func() {
		if errServe := srv.Serve(listener); errServe != nil && errServe != http.ErrServerClosed {
			log.WithError(errServe).Warn("kiro portal callback server stopped unexpectedly")
		}
		close(done)
	}()

	return &kiroPortalCallbackServer{
		port:     actualPort,
		server:   srv,
		listener: listener,
		done:     done,
	}, redirectURI, results, nil
}

func (s *kiroPortalCallbackServer) Close() {
	if s == nil || s.server == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.server.Shutdown(ctx); err != nil && err != http.ErrServerClosed {
		log.WithError(err).Warnf("failed to stop kiro portal callback server on port %d", s.port)
	}
	select {
	case <-s.done:
	case <-time.After(2 * time.Second):
	}
}

func exchangeKiroPortalSocialToken(ctx context.Context, client *http.Client, endpoint, code, codeVerifier, redirectURI string) (*kiroPortalTokenResponse, error) {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	payload, errMarshal := json.Marshal(kiroPortalTokenRequest{
		Code:         code,
		CodeVerifier: codeVerifier,
		RedirectURI:  redirectURI,
	})
	if errMarshal != nil {
		return nil, fmt.Errorf("failed to encode portal token request: %w", errMarshal)
	}
	req, errReq := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if errReq != nil {
		return nil, fmt.Errorf("failed to build portal token request: %w", errReq)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	fp := kiroauth.GlobalFingerprintManager().GetFingerprint("portal")
	req.Header.Set("User-Agent", fmt.Sprintf("KiroIDE-%s-%s", fp.KiroVersion, fp.KiroHash))

	resp, errDo := client.Do(req)
	if errDo != nil {
		return nil, fmt.Errorf("portal token request failed: %w", errDo)
	}
	defer resp.Body.Close()

	body, errRead := io.ReadAll(resp.Body)
	if errRead != nil {
		return nil, fmt.Errorf("failed to read portal token response: %w", errRead)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("portal token request failed (status %d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var result kiroPortalTokenResponse
	if errUnmarshal := json.Unmarshal(body, &result); errUnmarshal != nil {
		return nil, fmt.Errorf("failed to decode portal token response: %w", errUnmarshal)
	}
	if strings.TrimSpace(result.AccessToken) == "" || strings.TrimSpace(result.RefreshToken) == "" || result.ExpiresIn <= 0 {
		return nil, fmt.Errorf("portal token response missing required fields")
	}
	return &result, nil
}

func (h *Handler) portalHTTPClient() *http.Client {
	if h != nil && h.cfg != nil {
		return util.SetProxy(&h.cfg.SDKConfig, &http.Client{Timeout: 30 * time.Second})
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func (h *Handler) RequestKiroAWSAuthCodeToken(c *gin.Context) {
	state := fmt.Sprintf("kiro-authcode-%d", time.Now().UnixNano())
	h.startKiroAuthCodeFlow(c, state, "", "us-east-1", false)
}

func (h *Handler) RequestKiroIDCToken(c *gin.Context) {
	state := fmt.Sprintf("kiro-idc-%d", time.Now().UnixNano())
	startURL := strings.TrimSpace(c.Query("start_url"))
	if startURL == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "start_url is required for IDC login"})
		return
	}
	region := strings.TrimSpace(c.Query("region"))
	if region == "" {
		region = "us-east-1"
	}
	flow := strings.ToLower(strings.TrimSpace(c.Query("flow")))
	if flow == "" {
		flow = "authcode"
	}
	switch flow {
	case "authcode":
		h.startKiroAuthCodeFlow(c, state, startURL, region, true)
	case "device":
		h.startKiroIDCDeviceFlow(c, state, startURL, region)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid IDC flow, use 'authcode' or 'device'"})
	}
}

func (h *Handler) startKiroAuthCodeFlow(c *gin.Context, state, startURL, region string, isIDC bool) {
	ctx := context.Background()
	if region == "" {
		region = "us-east-1"
	}

	targetURL, errTarget := h.managementCallbackURL("/kiro/callback")
	if errTarget != nil {
		log.WithError(errTarget).Error("failed to compute kiro callback target")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "callback server unavailable"})
		return
	}
	forwarder, callbackPort, errForwarder := startKiroAuthCodeCallbackForwarder(kiroAuthCodeCallbackPort, targetURL)
	if errForwarder != nil {
		log.WithError(errForwarder).Error("failed to start kiro auth-code callback forwarder")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to start callback server"})
		return
	}
	redirectURI := fmt.Sprintf("http://127.0.0.1:%d/oauth/callback", callbackPort)

	codeVerifier, codeChallenge, errPKCE := generateKiroPKCE()
	if errPKCE != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate pkce"})
		return
	}

	ssoClient := kiroauth.NewSSOOIDCClient(h.cfg)
	var (
		regResp *kiroauth.RegisterClientResponse
		errReg  error
	)
	if isIDC {
		regResp, errReg = ssoClient.RegisterClientForAuthCodeWithIDC(ctx, redirectURI, startURL, region)
	} else {
		regResp, errReg = ssoClient.RegisterClientForAuthCode(ctx, redirectURI)
	}
	if errReg != nil {
		log.Errorf("Failed to register Kiro auth-code client: %v", errReg)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to register client"})
		return
	}

	endpoint := fmt.Sprintf("https://oidc.%s.amazonaws.com", region)
	if !isIDC {
		endpoint = "https://oidc.us-east-1.amazonaws.com"
	}
	scopes := "codewhisperer:completions,codewhisperer:analysis,codewhisperer:conversations"
	if isIDC {
		scopes = "codewhisperer:completions,codewhisperer:analysis,codewhisperer:conversations,codewhisperer:transformations,codewhisperer:taskassist"
	}
	authURL := buildKiroAuthCodeURL(endpoint, regResp.ClientID, redirectURI, scopes, state, codeChallenge)

	RegisterOAuthSession(state, "kiro")

	go func() {
		defer stopCallbackForwarderInstance(callbackPort, forwarder)

		waitFile := filepath.Join(h.cfg.AuthDir, fmt.Sprintf(".oauth-kiro-%s.oauth", state))
		deadline := time.Now().Add(10 * time.Minute)
		for {
			if !IsOAuthSessionPending(state, "kiro") {
				return
			}
			if time.Now().After(deadline) {
				SetOAuthSessionError(state, "OAuth flow timed out")
				return
			}
			if data, errRead := os.ReadFile(waitFile); errRead == nil {
				var m map[string]string
				_ = json.Unmarshal(data, &m)
				_ = os.Remove(waitFile)
				if errStr := strings.TrimSpace(m["error"]); errStr != "" {
					SetOAuthSessionError(state, "Authentication failed")
					return
				}
				if strings.TrimSpace(m["state"]) != state {
					SetOAuthSessionError(state, "State mismatch")
					return
				}
				code := strings.TrimSpace(m["code"])
				if code == "" {
					SetOAuthSessionError(state, "No authorization code received")
					return
				}

				var (
					tokenResp *kiroauth.CreateTokenResponse
					errToken  error
				)
				if isIDC {
					tokenResp, errToken = ssoClient.CreateTokenWithAuthCodeAndRegion(ctx, regResp.ClientID, regResp.ClientSecret, code, codeVerifier, redirectURI, region)
				} else {
					tokenResp, errToken = ssoClient.CreateTokenWithAuthCode(ctx, regResp.ClientID, regResp.ClientSecret, code, codeVerifier, redirectURI)
				}
				if errToken != nil {
					SetOAuthSessionError(state, "Failed to exchange authorization code for tokens")
					log.Errorf("Failed to exchange Kiro auth code for tokens: %v", errToken)
					return
				}

				expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
				tokenData := &kiroauth.KiroTokenData{
					AccessToken:  tokenResp.AccessToken,
					RefreshToken: tokenResp.RefreshToken,
					ExpiresAt:    expiresAt.Format(time.RFC3339),
					AuthMethod:   "builder-id",
					Provider:     "AWS",
					ClientID:     regResp.ClientID,
					ClientSecret: regResp.ClientSecret,
					Region:       region,
				}
				if isIDC {
					tokenData.ProfileArn = ssoClient.FetchProfileArn(ctx, tokenResp.AccessToken, regResp.ClientID, tokenResp.RefreshToken)
					tokenData.AuthMethod = "idc"
					tokenData.StartURL = startURL
				}
				tokenData.Email = kiroauth.FetchUserEmailWithFallback(ctx, h.cfg, tokenResp.AccessToken, regResp.ClientID, tokenResp.RefreshToken)

				savedPath, errSave := h.saveKiroTokenDataRecord(ctx, tokenData)
				if errSave != nil {
					SetOAuthSessionError(state, "Failed to save authentication tokens")
					log.Errorf("Failed to save Kiro auth-code tokens: %v", errSave)
					return
				}

				fmt.Printf("Kiro auth-code authentication successful! Token saved to %s\n", savedPath)
				CompleteOAuthSession(state)
				CompleteOAuthSessionsByProvider("kiro")
				return
			}
			time.Sleep(500 * time.Millisecond)
		}
	}()

	c.JSON(http.StatusOK, gin.H{"status": "ok", "url": authURL, "state": state, "method": "auth_code"})
}

func startKiroAuthCodeCallbackForwarder(preferredPort int, targetBase string) (*callbackForwarder, int, error) {
	if preferredPort <= 0 {
		return nil, 0, fmt.Errorf("preferred callback port must be positive")
	}

	if forwarder, err := startCallbackForwarder(preferredPort, "kiro-authcode", targetBase); err == nil {
		return forwarder, preferredPort, nil
	}

	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		return nil, 0, fmt.Errorf("failed to listen on fallback callback port: %w", err)
	}
	actualPort := ln.Addr().(*net.TCPAddr).Port

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := targetBase
		if raw := r.URL.RawQuery; raw != "" {
			if strings.Contains(target, "?") {
				target += "&" + raw
			} else {
				target += "?" + raw
			}
		}
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, target, http.StatusFound)
	})

	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      5 * time.Second,
	}
	done := make(chan struct{})

	go func() {
		if errServe := srv.Serve(ln); errServe != nil && errServe != http.ErrServerClosed {
			log.WithError(errServe).Warn("kiro auth-code fallback callback forwarder stopped unexpectedly")
		}
		close(done)
	}()

	forwarder := &callbackForwarder{
		provider: "kiro-authcode",
		server:   srv,
		done:     done,
	}

	callbackForwardersMu.Lock()
	callbackForwarders[actualPort] = forwarder
	callbackForwardersMu.Unlock()

	log.Warnf("callback forwarder for kiro-authcode default port %d is busy, using fallback port %d", preferredPort, actualPort)
	return forwarder, actualPort, nil
}

func (h *Handler) startKiroIDCDeviceFlow(c *gin.Context, state, startURL, region string) {
	ctx := context.Background()
	ssoClient := kiroauth.NewSSOOIDCClient(h.cfg)

	regResp, errRegister := ssoClient.RegisterClientWithRegion(ctx, region)
	if errRegister != nil {
		log.Errorf("Failed to register Kiro IDC client: %v", errRegister)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to register client"})
		return
	}

	authResp, errAuth := ssoClient.StartDeviceAuthorizationWithIDC(ctx, regResp.ClientID, regResp.ClientSecret, startURL, region)
	if errAuth != nil {
		log.Errorf("Failed to start Kiro IDC device authorization: %v", errAuth)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to start device authorization"})
		return
	}

	RegisterOAuthSession(state, "kiro")
	SetOAuthSessionError(state, "device_code|"+authResp.VerificationURIComplete+"|"+authResp.UserCode)

	go func() {
		interval := 5 * time.Second
		if authResp.Interval > 0 {
			interval = time.Duration(authResp.Interval) * time.Second
		}
		deadline := time.Now().Add(time.Duration(authResp.ExpiresIn) * time.Second)

		for time.Now().Before(deadline) {
			select {
			case <-ctx.Done():
				SetOAuthSessionError(state, "Authorization cancelled")
				return
			case <-time.After(interval):
				tokenResp, errToken := ssoClient.CreateTokenWithRegion(ctx, regResp.ClientID, regResp.ClientSecret, authResp.DeviceCode, region)
				if errToken != nil {
					errStr := errToken.Error()
					if strings.Contains(errStr, "authorization_pending") {
						continue
					}
					if strings.Contains(errStr, "slow_down") {
						interval += 5 * time.Second
						continue
					}
					SetOAuthSessionError(state, "Token creation failed")
					log.Errorf("Kiro IDC device token creation failed: %v", errToken)
					return
				}

				expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
				tokenData := &kiroauth.KiroTokenData{
					AccessToken:  tokenResp.AccessToken,
					RefreshToken: tokenResp.RefreshToken,
					ProfileArn:   ssoClient.FetchProfileArn(ctx, tokenResp.AccessToken, regResp.ClientID, tokenResp.RefreshToken),
					ExpiresAt:    expiresAt.Format(time.RFC3339),
					AuthMethod:   "idc",
					Provider:     "AWS",
					ClientID:     regResp.ClientID,
					ClientSecret: regResp.ClientSecret,
					Email:        kiroauth.FetchUserEmailWithFallback(ctx, h.cfg, tokenResp.AccessToken, regResp.ClientID, tokenResp.RefreshToken),
					StartURL:     startURL,
					Region:       region,
				}

				savedPath, errSave := h.saveKiroTokenDataRecord(ctx, tokenData)
				if errSave != nil {
					SetOAuthSessionError(state, "Failed to save authentication tokens")
					log.Errorf("Failed to save Kiro IDC tokens: %v", errSave)
					return
				}

				fmt.Printf("Kiro IDC device authentication successful! Token saved to %s\n", savedPath)
				CompleteOAuthSession(state)
				CompleteOAuthSessionsByProvider("kiro")
				return
			}
		}

		SetOAuthSessionError(state, "Authorization timed out")
	}()

	c.JSON(http.StatusOK, gin.H{
		"status":           "ok",
		"state":            state,
		"method":           "device_code",
		"url":              authResp.VerificationURIComplete,
		"user_code":        authResp.UserCode,
		"verification_uri": authResp.VerificationURIComplete,
	})
}

func buildKiroAuthCodeURL(endpoint, clientID, redirectURI, scopes, state, codeChallenge string) string {
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", clientID)
	params.Set("redirect_uri", redirectURI)
	params.Set("scopes", scopes)
	params.Set("state", state)
	params.Set("code_challenge", codeChallenge)
	params.Set("code_challenge_method", "S256")
	return endpoint + "/authorize?" + params.Encode()
}

func (h *Handler) saveKiroTokenDataRecord(ctx context.Context, tokenData *kiroauth.KiroTokenData) (string, error) {
	if tokenData == nil {
		return "", fmt.Errorf("kiro token data is nil")
	}

	fileName := kiroauth.GenerateTokenFileName(tokenData)
	record := &coreauth.Auth{
		ID:       fileName,
		Provider: "kiro",
		FileName: fileName,
		Label:    strings.TrimSuffix(fileName, ".json"),
		Metadata: map[string]any{
			"type":           "kiro",
			"access_token":   tokenData.AccessToken,
			"refresh_token":  tokenData.RefreshToken,
			"profile_arn":    tokenData.ProfileArn,
			"expires_at":     tokenData.ExpiresAt,
			"auth_method":    tokenData.AuthMethod,
			"provider":       tokenData.Provider,
			"client_id":      tokenData.ClientID,
			"client_secret":  tokenData.ClientSecret,
			"client_id_hash": tokenData.ClientIDHash,
			"email":          tokenData.Email,
			"region":         tokenData.Region,
			"start_url":      tokenData.StartURL,
			"last_refresh":   time.Now().Format(time.RFC3339),
		},
		Attributes: map[string]string{
			"profile_arn": tokenData.ProfileArn,
			"email":       tokenData.Email,
			"region":      tokenData.Region,
			"start_url":   tokenData.StartURL,
		},
	}
	return h.saveTokenRecord(ctx, record)
}

func (h *Handler) ImportKiroToken(c *gin.Context) {
	record, err := sdkAuth.NewKiroAuthenticator().ImportFromKiroIDE(context.Background(), h.cfg)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": err.Error()})
		return
	}
	savedPath, errSave := h.saveTokenRecord(context.Background(), record)
	if errSave != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "error": "failed to save imported token"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok", "saved_path": savedPath, "label": record.Label})
}

func (h *Handler) RequestCodeBuddyToken(c *gin.Context) {
	ctx := context.Background()

	fmt.Println("Initializing CodeBuddy authentication...")

	authSvc := codebuddyauth.NewCodeBuddyAuth(h.cfg)
	authState, err := authSvc.FetchAuthState(ctx)
	if err != nil {
		log.Errorf("Failed to initialize CodeBuddy authentication: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to initialize codebuddy authentication"})
		return
	}

	state := strings.TrimSpace(authState.State)
	if state == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "codebuddy auth state is empty"})
		return
	}

	RegisterOAuthSession(state, "codebuddy")

	go func() {
		storage, errPoll := authSvc.PollForToken(ctx, state)
		if errPoll != nil {
			SetOAuthSessionError(state, oauthSessionErrorWithCause("Authentication failed", errPoll))
			log.Errorf("CodeBuddy authentication failed: %v", errPoll)
			return
		}

		fileName := fmt.Sprintf("codebuddy-%s.json", storage.UserID)
		label := strings.TrimSpace(storage.UserID)
		if label == "" {
			label = "codebuddy-user"
		}

		record := &coreauth.Auth{
			ID:       fileName,
			Provider: "codebuddy",
			FileName: fileName,
			Label:    label,
			Storage:  storage,
			Metadata: map[string]any{
				"access_token":  storage.AccessToken,
				"refresh_token": storage.RefreshToken,
				"user_id":       storage.UserID,
				"domain":        storage.Domain,
				"expires_in":    storage.ExpiresIn,
			},
		}

		savedPath, errSave := h.saveTokenRecord(ctx, record)
		if errSave != nil {
			SetOAuthSessionError(state, "Failed to save authentication tokens")
			log.Errorf("Failed to save CodeBuddy authentication tokens: %v", errSave)
			return
		}

		fmt.Printf("CodeBuddy authentication successful! Token saved to %s\n", savedPath)
		CompleteOAuthSession(state)
		CompleteOAuthSessionsByProvider("codebuddy")
	}()

	c.JSON(http.StatusOK, gin.H{"status": "ok", "url": authState.AuthURL, "state": state})
}
