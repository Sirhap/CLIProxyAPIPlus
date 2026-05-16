package management

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
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
	kiroAuthCodeCallbackPort            = 19877
)

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
	forwarder, errForwarder := startCallbackForwarder(kiroAuthCodeCallbackPort, "kiro-authcode", targetURL)
	if errForwarder != nil {
		log.WithError(errForwarder).Error("failed to start kiro auth-code callback forwarder")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to start callback server"})
		return
	}
	redirectURI := fmt.Sprintf("http://127.0.0.1:%d/oauth/callback", kiroAuthCodeCallbackPort)

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
		defer stopCallbackForwarderInstance(kiroAuthCodeCallbackPort, forwarder)

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
