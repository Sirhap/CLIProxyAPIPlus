package management

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	kiroauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/kiro"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/proxyutil"
	log "github.com/sirupsen/logrus"
)

const (
	windsurfFirebaseAPIKey     = "AIzaSyDsOl-1XpT5err0Tcnx8FFod1H8gVGIycY"
	windsurfLoginTimeout       = 30 * time.Second
	windsurfEmailLockThreshold = 3
	windsurfEmailLockDuration  = 15 * time.Minute
	windsurfEmailLockIdleTTL   = 2 * time.Hour
)

var (
	windsurfFirebaseAuthURL       = "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=" + windsurfFirebaseAPIKey
	windsurfAuth1ConnectionsURL   = "https://windsurf.com/_devin-auth/connections"
	windsurfAuth1PasswordLoginURL = "https://windsurf.com/_devin-auth/password/login"
	windsurfCheckLoginMethodURL   = "https://windsurf.com/_backend/exa.seat_management_pb.SeatManagementService/CheckUserLoginMethod"
	windsurfPostAuthURLNew        = "https://windsurf.com/_backend/exa.seat_management_pb.SeatManagementService/WindsurfPostAuth"
	windsurfPostAuthURLLegacy     = "https://server.self-serve.windsurf.com/exa.seat_management_pb.SeatManagementService/WindsurfPostAuth"
	windsurfGetUserStatusPath     = "/exa.seat_management_pb.SeatManagementService/GetUserStatus"
	windsurfRegisterURLs          = []windsurfEndpoint{
		{URL: "https://register.windsurf.com/exa.seat_management_pb.SeatManagementService/RegisterUser", Label: "new"},
		{URL: "https://api.codeium.com/register_user/", Label: "legacy"},
	}
	windsurfSessionTokenRE = regexp.MustCompile(`devin-session-token\$[a-zA-Z0-9._-]+`)
	windsurfAccountIDRE    = regexp.MustCompile(`account-[a-fA-F0-9]+`)
	windsurfOrgIDRE        = regexp.MustCompile(`org-[a-fA-F0-9]+`)
)

type windsurfEndpoint struct {
	URL   string
	Label string
}

type windsurfLoginRequest struct {
	Email          string          `json:"email"`
	Password       string          `json:"password"`
	ProxyURL       string          `json:"proxy_url"`
	ProxyURLDash   string          `json:"proxy-url"`
	Proxy          json.RawMessage `json:"proxy"`
	LSBinaryPath   string          `json:"ls_binary_path"`
	LSDataDir      string          `json:"ls_data_dir"`
	WorkspaceDir   string          `json:"workspace_dir"`
	APIServerURL   string          `json:"api_server_url"`
	Transport      string          `json:"transport"`
	LSMaxInstances any             `json:"ls_max_instances"`
	Priority       any             `json:"priority"`
	ExcludedModels []string        `json:"excluded_models"`
}

type windsurfLoginMethod struct {
	Method      string
	HasPassword bool
	Raw         map[string]any
}

type windsurfLoginResult struct {
	APIKey       string
	Name         string
	Email        string
	IDToken      string
	RefreshToken string
	APIServerURL string
	SessionToken string
	Auth1Token   string
	AccountID    string
	OrgID        string
	AuthMethod   string
	Source       string
}

type windsurfRegisterResult struct {
	APIKey       string
	Name         string
	APIServerURL string
	Source       string
}

type windsurfQuotaRequest struct {
	Name string `json:"name"`
}

type windsurfQuotaResponse struct {
	PlanName                    string   `json:"plan_name,omitempty"`
	Email                       string   `json:"email,omitempty"`
	MonthlyPromptCredits        *float64 `json:"monthly_prompt_credits,omitempty"`
	MonthlyFlowCredits          *float64 `json:"monthly_flow_credits,omitempty"`
	AvailablePromptCredits      *float64 `json:"available_prompt_credits,omitempty"`
	UsedPromptCredits           *float64 `json:"used_prompt_credits,omitempty"`
	AvailableFlexCredits        *float64 `json:"available_flex_credits,omitempty"`
	DailyQuotaRemainingPercent  *float64 `json:"daily_quota_remaining_percent,omitempty"`
	WeeklyQuotaRemainingPercent *float64 `json:"weekly_quota_remaining_percent,omitempty"`
	DailyQuotaResetAtUnix       string   `json:"daily_quota_reset_at_unix,omitempty"`
	WeeklyQuotaResetAtUnix      string   `json:"weekly_quota_reset_at_unix,omitempty"`
	BillingStrategy             string   `json:"billing_strategy,omitempty"`
	TeamsTier                   string   `json:"teams_tier,omitempty"`
	SourceURL                   string   `json:"source_url,omitempty"`
}

type windsurfLoginError struct {
	Code       string
	StatusCode int
	IsAuthFail bool
	RetryAfter time.Duration
	Cause      error
}

func (e *windsurfLoginError) Error() string {
	if e == nil {
		return ""
	}
	if e.Code != "" {
		return e.Code
	}
	if e.Cause != nil {
		return e.Cause.Error()
	}
	return "windsurf login failed"
}

type windsurfEmailFailure struct {
	Count        int
	LockedUntil  time.Time
	LastActivity time.Time
	LastReason   string
}

var windsurfLoginFailures = struct {
	sync.Mutex
	items map[string]*windsurfEmailFailure
}{items: make(map[string]*windsurfEmailFailure)}

func init() {
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			windsurfPurgeLoginFailures()
		}
	}()
}

func (h *Handler) RequestWindsurfToken(c *gin.Context) {
	ctx := PopulateAuthContext(context.Background(), c)

	var req windsurfLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid windsurf login request"})
		return
	}

	email := strings.TrimSpace(req.Email)
	password := req.Password
	if strings.TrimSpace(email) == "" || password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ERR_EMAIL_PASSWORD_REQUIRED"})
		return
	}

	proxyURL := windsurfProxyURLFromRequest(req)
	httpClient, errClient := windsurfLoginHTTPClient(h.cfg, proxyURL)
	if errClient != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": errClient.Error()})
		return
	}

	result, errLogin := windsurfLogin(ctx, httpClient, email, password, proxyURL)
	if errLogin != nil {
		status := http.StatusBadRequest
		payload := gin.H{"error": errLogin.Error()}
		var loginErr *windsurfLoginError
		if errors.As(errLogin, &loginErr) {
			if loginErr.StatusCode > 0 {
				status = loginErr.StatusCode
			}
			payload["isAuthFail"] = loginErr.IsAuthFail
			if loginErr.RetryAfter > 0 {
				payload["retry_after_ms"] = loginErr.RetryAfter.Milliseconds()
			}
		}
		c.JSON(status, payload)
		return
	}

	metadata := windsurfAuthMetadataFromLogin(req, result, proxyURL)
	fileName := "windsurf-" + kiroauth.SanitizeEmailForFilename(email) + ".json"
	if fileName == "windsurf-.json" {
		fileName = fmt.Sprintf("windsurf-%d.json", time.Now().UnixNano())
	}
	record := &coreauth.Auth{
		ID:       fileName,
		Provider: "windsurf",
		FileName: fileName,
		ProxyURL: proxyURL,
		Metadata: metadata,
	}

	savedPath, errSave := h.saveTokenRecord(ctx, record)
	if errSave != nil {
		log.Errorf("Failed to save Windsurf auth: %v", errSave)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save windsurf authentication"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":         "ok",
		"provider":       "windsurf",
		"path":           savedPath,
		"email":          email,
		"name":           result.Name,
		"auth_method":    result.AuthMethod,
		"api_key_masked": windsurfMaskSecret(result.APIKey),
	})
}

func (h *Handler) GetWindsurfAuthFileQuota(c *gin.Context) {
	if h.authManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "core auth manager unavailable"})
		return
	}

	var req windsurfQuotaRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}

	auth := h.findManagedAuthByName(name)
	if auth == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "auth file not found"})
		return
	}
	if strings.ToLower(strings.TrimSpace(auth.Provider)) != "windsurf" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "auth file is not a Windsurf credential"})
		return
	}

	quota, err := h.fetchWindsurfQuota(c.Request.Context(), auth)
	if err != nil {
		var loginErr *windsurfLoginError
		if errors.As(err, &loginErr) && loginErr.StatusCode > 0 {
			c.JSON(loginErr.StatusCode, gin.H{"error": loginErr.Error()})
			return
		}
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":   "ok",
		"name":     name,
		"id":       auth.ID,
		"provider": "windsurf",
		"quota":    quota,
	})
}

func (h *Handler) findManagedAuthByName(name string) *coreauth.Auth {
	if h == nil || h.authManager == nil {
		return nil
	}
	if auth, ok := h.authManager.GetByID(name); ok {
		return auth
	}
	for _, auth := range h.authManager.List() {
		if auth != nil && auth.FileName == name {
			return auth
		}
	}
	return nil
}

func (h *Handler) fetchWindsurfQuota(ctx context.Context, auth *coreauth.Auth) (windsurfQuotaResponse, error) {
	if auth == nil {
		return windsurfQuotaResponse{}, fmt.Errorf("auth file not found")
	}
	apiKey := strings.TrimSpace(windsurfStringFromMetadata(auth, "api_key", "session_token"))
	if apiKey == "" {
		return windsurfQuotaResponse{}, &windsurfLoginError{Code: "windsurf credential is missing api_key/session_token", StatusCode: http.StatusUnauthorized}
	}
	proxyURL := strings.TrimSpace(windsurfStringFromMetadata(auth, "proxy_url"))
	client, errClient := windsurfLoginHTTPClient(h.cfg, proxyURL)
	if errClient != nil {
		return windsurfQuotaResponse{}, errClient
	}

	body := []byte(mustJSON(map[string]any{
		"metadata": map[string]any{
			"apiKey":           apiKey,
			"ideName":          "windsurf",
			"ideVersion":       "0.0.0",
			"extensionName":    "windsurf",
			"extensionVersion": "0.0.0",
			"locale":           "en",
		},
	}))
	headers := map[string]string{
		"Content-Type":             "application/json",
		"Content-Length":           strconv.Itoa(len(body)),
		"Connect-Protocol-Version": "1",
		"Accept":                   "application/json",
		"User-Agent":               "windsurf/1.9600.41",
	}

	var endpoints []windsurfEndpoint
	if baseURL := strings.TrimRight(strings.TrimSpace(windsurfStringFromMetadata(auth, "api_server_url")), "/"); baseURL != "" {
		endpoints = append(endpoints, windsurfEndpoint{URL: baseURL + windsurfGetUserStatusPath, Label: "credential"})
	}
	endpoints = append(endpoints,
		windsurfEndpoint{URL: "https://server.codeium.com" + windsurfGetUserStatusPath, Label: "codeium"},
		windsurfEndpoint{URL: "https://server.self-serve.windsurf.com" + windsurfGetUserStatusPath, Label: "windsurf"},
	)

	var lastErr error
	seen := make(map[string]bool)
	for _, endpoint := range endpoints {
		if endpoint.URL == "" || seen[endpoint.URL] {
			continue
		}
		seen[endpoint.URL] = true
		resp, err := windsurfDoRequest(ctx, client, endpoint.URL, headers, body, false)
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", endpoint.Label, err)
			continue
		}
		if resp.Status == http.StatusUnauthorized || resp.Status == http.StatusForbidden {
			return windsurfQuotaResponse{}, &windsurfLoginError{Code: fmt.Sprintf("Windsurf quota HTTP %d", resp.Status), StatusCode: resp.Status}
		}
		if resp.Status >= 400 {
			lastErr = fmt.Errorf("%s: HTTP %d %s", endpoint.Label, resp.Status, windsurfTruncate(string(resp.Raw), 240))
			continue
		}
		quota := windsurfQuotaFromUserStatus(resp.JSON)
		quota.SourceURL = endpoint.URL
		if quota.Email == "" {
			quota.Email = strings.TrimSpace(windsurfStringFromMetadata(auth, "email"))
		}
		return quota, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("Windsurf quota endpoint did not return data")
	}
	return windsurfQuotaResponse{}, lastErr
}

func windsurfLogin(ctx context.Context, client *http.Client, email, password, proxyURL string) (windsurfLoginResult, error) {
	if retryAfter := windsurfEmailLockedFor(email); retryAfter > 0 {
		return windsurfLoginResult{}, &windsurfLoginError{
			Code:       fmt.Sprintf("Email %s is locally locked after repeated failed Windsurf logins; retry later.", email),
			StatusCode: http.StatusTooManyRequests,
			RetryAfter: retryAfter,
		}
	}

	fingerprint := windsurfGenerateFingerprint()
	log.Debugf("windsurf login: email=%s proxy=%s", email, proxyutil.Redact(proxyURL))

	conn, errProbe := windsurfFetchCheckUserLoginMethod(ctx, client, email, fingerprint)
	if errProbe != nil {
		log.Debugf("windsurf CheckUserLoginMethod failed: %v", errProbe)
	}
	if conn == nil || conn.Method == "" {
		if legacy, errLegacy := windsurfFetchAuth1Connections(ctx, client, email, fingerprint); errLegacy == nil {
			conn = legacy
		} else {
			log.Debugf("windsurf auth1 connections failed: %v", errLegacy)
		}
	}

	if conn != nil && conn.Method == "auth1" {
		if !conn.HasPassword {
			errNoPassword := windsurfFriendlyAuthError("Auth1", "No password set", "ERR_NO_PASSWORD_SET")
			windsurfRecordLoginFailure(email, errNoPassword)
			return windsurfLoginResult{}, errNoPassword
		}
		result, errAuth1 := windsurfLoginViaAuth1(ctx, client, email, password, fingerprint)
		if errAuth1 == nil {
			windsurfRecordLoginSuccess(email)
			return result, nil
		}
		if windsurfShouldCountLoginFailure(errAuth1) {
			windsurfRecordLoginFailure(email, errAuth1)
		}
		return windsurfLoginResult{}, errAuth1
	}

	result, errFirebase := windsurfLoginViaFirebase(ctx, client, email, password, fingerprint)
	if errFirebase == nil {
		windsurfRecordLoginSuccess(email)
		return result, nil
	}
	if !windsurfShouldCountLoginFailure(errFirebase) {
		return windsurfLoginResult{}, errFirebase
	}

	result, errAuth1 := windsurfLoginViaAuth1(ctx, client, email, password, fingerprint)
	if errAuth1 == nil {
		windsurfRecordLoginSuccess(email)
		return result, nil
	}
	windsurfRecordLoginFailure(email, errFirebase)
	return windsurfLoginResult{}, errFirebase
}

func windsurfLoginViaAuth1(ctx context.Context, client *http.Client, email, password string, fingerprint map[string]string) (windsurfLoginResult, error) {
	body := []byte(mustJSON(map[string]string{"email": email, "password": password}))
	resp, err := windsurfRequestRetrying(ctx, client, windsurfAuth1PasswordLoginURL, windsurfBuildJSONHeaders(fingerprint, body, nil), body, false, "Auth1 password/login")
	if err != nil {
		return windsurfLoginResult{}, err
	}

	detail := windsurfDetailMessage(resp.JSON["detail"])
	if resp.Status >= 400 || detail != "" {
		return windsurfLoginResult{}, windsurfFriendlyAuthError("Auth1", detail, "ERR_LOGIN_FAILED")
	}
	auth1Token, _ := resp.JSON["token"].(string)
	auth1Token = strings.TrimSpace(auth1Token)
	if auth1Token == "" {
		return windsurfLoginResult{}, &windsurfLoginError{Code: "ERR_AUTH1_TOKEN_MISSING", StatusCode: http.StatusBadGateway}
	}

	postAuth, label, errPostAuth := windsurfPostAuthDualPath(ctx, client, auth1Token, fingerprint)
	if errPostAuth != nil {
		return windsurfLoginResult{}, errPostAuth
	}
	sessionToken, _ := postAuth["sessionToken"].(string)
	sessionToken = strings.TrimSpace(sessionToken)
	if sessionToken == "" {
		return windsurfLoginResult{}, &windsurfLoginError{Code: "ERR_POSTAUTH_FAILED", StatusCode: http.StatusBadGateway}
	}
	accountID, _ := postAuth["accountId"].(string)
	orgID, _ := postAuth["primaryOrgId"].(string)

	return windsurfLoginResult{
		APIKey:       sessionToken,
		Name:         email,
		Email:        email,
		SessionToken: sessionToken,
		Auth1Token:   auth1Token,
		AccountID:    strings.TrimSpace(accountID),
		OrgID:        strings.TrimSpace(orgID),
		AuthMethod:   "auth1",
		Source:       label,
	}, nil
}

func windsurfLoginViaFirebase(ctx context.Context, client *http.Client, email, password string, fingerprint map[string]string) (windsurfLoginResult, error) {
	body := []byte(mustJSON(map[string]any{
		"email":             email,
		"password":          password,
		"returnSecureToken": true,
	}))
	resp, err := windsurfDoRequest(ctx, client, windsurfFirebaseAuthURL, windsurfBuildJSONHeaders(fingerprint, body, nil), body, false)
	if err != nil {
		return windsurfLoginResult{}, err
	}
	if rawErr, ok := resp.JSON["error"]; ok && rawErr != nil {
		msg := "ERR_LOGIN_FAILED"
		if m, okMap := rawErr.(map[string]any); okMap {
			if s, okMsg := m["message"].(string); okMsg && strings.TrimSpace(s) != "" {
				msg = s
			}
		}
		return windsurfLoginResult{}, windsurfFriendlyAuthError("Firebase", msg, msg)
	}
	if resp.Status >= 400 {
		return windsurfLoginResult{}, &windsurfLoginError{Code: fmt.Sprintf("Firebase HTTP %d", resp.Status), StatusCode: http.StatusBadGateway}
	}
	idToken, _ := resp.JSON["idToken"].(string)
	idToken = strings.TrimSpace(idToken)
	if idToken == "" {
		return windsurfLoginResult{}, &windsurfLoginError{Code: "ERR_FIREBASE_TOKEN_MISSING", StatusCode: http.StatusBadGateway}
	}
	refreshToken, _ := resp.JSON["refreshToken"].(string)

	reg, errRegister := windsurfRegisterWithFirebaseToken(ctx, client, idToken, fingerprint)
	if errRegister != nil {
		return windsurfLoginResult{}, errRegister
	}
	name := strings.TrimSpace(reg.Name)
	if name == "" {
		name = email
	}
	return windsurfLoginResult{
		APIKey:       reg.APIKey,
		Name:         name,
		Email:        email,
		IDToken:      idToken,
		RefreshToken: strings.TrimSpace(refreshToken),
		APIServerURL: reg.APIServerURL,
		AuthMethod:   "firebase",
		Source:       reg.Source,
	}, nil
}

func windsurfFetchCheckUserLoginMethod(ctx context.Context, client *http.Client, email string, fingerprint map[string]string) (*windsurfLoginMethod, error) {
	body := []byte(mustJSON(map[string]string{"email": email}))
	headers := windsurfBuildJSONHeaders(fingerprint, body, map[string]string{"Connect-Protocol-Version": "1"})
	resp, err := windsurfDoRequest(ctx, client, windsurfCheckLoginMethodURL, headers, body, false)
	if err != nil {
		return nil, err
	}
	if resp.Status != http.StatusOK || len(resp.JSON) == 0 {
		return nil, nil
	}
	_, hasUserExists := resp.JSON["userExists"]
	_, hasPasswordField := resp.JSON["hasPassword"]
	if !hasUserExists && !hasPasswordField {
		return nil, nil
	}
	if v, ok := resp.JSON["userExists"].(bool); ok && !v {
		return &windsurfLoginMethod{Method: "", HasPassword: false, Raw: resp.JSON}, nil
	}
	hasPassword, _ := resp.JSON["hasPassword"].(bool)
	return &windsurfLoginMethod{Method: "auth1", HasPassword: hasPassword, Raw: resp.JSON}, nil
}

func windsurfFetchAuth1Connections(ctx context.Context, client *http.Client, email string, fingerprint map[string]string) (*windsurfLoginMethod, error) {
	body := []byte(mustJSON(map[string]string{"product": "windsurf", "email": email}))
	resp, err := windsurfRequestRetrying(ctx, client, windsurfAuth1ConnectionsURL, windsurfBuildJSONHeaders(fingerprint, body, nil), body, false, "Auth1 connections")
	if err != nil {
		return nil, err
	}
	return windsurfInterpretConnections(resp.JSON), nil
}

func windsurfInterpretConnections(data map[string]any) *windsurfLoginMethod {
	if data == nil {
		return &windsurfLoginMethod{}
	}
	if rawConnections, ok := data["connections"].([]any); ok {
		for _, raw := range rawConnections {
			conn, okConn := raw.(map[string]any)
			if !okConn {
				continue
			}
			if typ, _ := conn["type"].(string); typ != "email" {
				continue
			}
			enabled, _ := conn["enabled"].(bool)
			return &windsurfLoginMethod{Method: "auth1", HasPassword: enabled, Raw: data}
		}
		return &windsurfLoginMethod{Method: "auth1", HasPassword: false, Raw: data}
	}
	if rawAuthMethod, ok := data["auth_method"].(map[string]any); ok {
		method, _ := rawAuthMethod["method"].(string)
		hasPassword := true
		if v, okPw := rawAuthMethod["has_password"].(bool); okPw {
			hasPassword = v
		}
		return &windsurfLoginMethod{Method: strings.TrimSpace(method), HasPassword: hasPassword, Raw: data}
	}
	return &windsurfLoginMethod{Raw: data}
}

func windsurfPostAuthDualPath(ctx context.Context, client *http.Client, auth1Token string, fingerprint map[string]string) (map[string]any, string, error) {
	headers := make(map[string]string, len(fingerprint)+5)
	for k, v := range fingerprint {
		headers[k] = v
	}
	headers["Content-Type"] = "application/proto"
	headers["Content-Length"] = "0"
	headers["Connect-Protocol-Version"] = "1"
	headers["X-Devin-Auth1-Token"] = auth1Token
	headers["Referer"] = "https://windsurf.com/account/login"

	endpoints := []windsurfEndpoint{
		{URL: windsurfPostAuthURLNew, Label: "new"},
		{URL: windsurfPostAuthURLLegacy, Label: "legacy"},
	}
	var lastErr error
	for _, endpoint := range endpoints {
		resp, err := windsurfDoRequest(ctx, client, endpoint.URL, headers, nil, true)
		if err != nil {
			lastErr = fmt.Errorf("PostAuth %s: %w", endpoint.Label, err)
			continue
		}
		parsed := windsurfParsePostAuthResponse(resp.Raw)
		if resp.Status >= 400 && resp.Status < 500 {
			return parsed, endpoint.Label, &windsurfLoginError{Code: fmt.Sprintf("ERR_POSTAUTH_FAILED:%s", windsurfJSONSummary(parsed)), StatusCode: http.StatusUnauthorized}
		}
		if resp.Status >= 200 && resp.Status < 300 {
			if sessionToken, _ := parsed["sessionToken"].(string); strings.TrimSpace(sessionToken) != "" {
				return parsed, endpoint.Label, nil
			}
		}
		lastErr = fmt.Errorf("PostAuth %s HTTP %d: %s", endpoint.Label, resp.Status, windsurfJSONSummary(parsed))
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("PostAuth: both endpoints failed")
	}
	return nil, "", &windsurfLoginError{Code: lastErr.Error(), StatusCode: http.StatusBadGateway, Cause: lastErr}
}

func windsurfRegisterWithFirebaseToken(ctx context.Context, client *http.Client, token string, fingerprint map[string]string) (windsurfRegisterResult, error) {
	body := []byte(mustJSON(map[string]string{"firebase_id_token": token}))
	headers := windsurfBuildJSONHeaders(fingerprint, body, map[string]string{
		"Connect-Protocol-Version": "1",
		"Accept":                   "application/json",
		"User-Agent":               "windsurf/1.9600.41",
	})

	var errs []string
	for _, endpoint := range windsurfRegisterURLs {
		resp, err := windsurfDoRequest(ctx, client, endpoint.URL, headers, body, false)
		if err != nil {
			errs = append(errs, endpoint.Label+"="+err.Error())
			continue
		}
		apiKey, _ := resp.JSON["api_key"].(string)
		if strings.TrimSpace(apiKey) == "" {
			apiKey, _ = resp.JSON["apiKey"].(string)
		}
		if resp.Status < 400 && strings.TrimSpace(apiKey) != "" {
			name, _ := resp.JSON["name"].(string)
			apiServerURL, _ := resp.JSON["api_server_url"].(string)
			if strings.TrimSpace(apiServerURL) == "" {
				apiServerURL, _ = resp.JSON["apiServerUrl"].(string)
			}
			return windsurfRegisterResult{
				APIKey:       strings.TrimSpace(apiKey),
				Name:         strings.TrimSpace(name),
				APIServerURL: strings.TrimSpace(apiServerURL),
				Source:       endpoint.Label,
			}, nil
		}
		errs = append(errs, fmt.Sprintf("%s=HTTP %d %s", endpoint.Label, resp.Status, string(resp.Raw)))
	}
	return windsurfRegisterResult{}, &windsurfLoginError{Code: "ERR_CODEIUM_REGISTER_FAILED:" + strings.Join(errs, " | "), StatusCode: http.StatusUnauthorized}
}

type windsurfHTTPResponse struct {
	Status int
	Raw    []byte
	JSON   map[string]any
}

func windsurfRequestRetrying(ctx context.Context, client *http.Client, endpoint string, headers map[string]string, body []byte, raw bool, label string) (windsurfHTTPResponse, error) {
	var lastErr error
	delays := []time.Duration{0, 2 * time.Second, 5 * time.Second}
	for i, delay := range delays {
		if delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return windsurfHTTPResponse{}, ctx.Err()
			case <-timer.C:
			}
		}
		resp, err := windsurfDoRequest(ctx, client, endpoint, headers, body, raw)
		if err != nil {
			lastErr = err
			log.Debugf("%s failed on attempt %d/%d: %v", label, i+1, len(delays), err)
			continue
		}
		if resp.Status >= 500 && resp.Status < 600 {
			lastErr = fmt.Errorf("%s upstream HTTP %d: %s", label, resp.Status, string(resp.Raw))
			continue
		}
		return resp, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("%s failed after retries", label)
	}
	return windsurfHTTPResponse{}, lastErr
}

func windsurfDoRequest(ctx context.Context, client *http.Client, endpoint string, headers map[string]string, body []byte, raw bool) (windsurfHTTPResponse, error) {
	if client == nil {
		client = &http.Client{Timeout: windsurfLoginTimeout}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return windsurfHTTPResponse{}, fmt.Errorf("create request failed: %w", err)
	}
	for k, v := range headers {
		if strings.TrimSpace(k) != "" {
			req.Header.Set(k, v)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return windsurfHTTPResponse{}, fmt.Errorf("request failed: %w", err)
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.Debugf("windsurf login response close failed: %v", errClose)
		}
	}()
	rawBody, errRead := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if errRead != nil {
		return windsurfHTTPResponse{}, fmt.Errorf("read response failed: %w", errRead)
	}
	out := windsurfHTTPResponse{Status: resp.StatusCode, Raw: rawBody}
	if raw {
		return out, nil
	}
	if len(bytes.TrimSpace(rawBody)) == 0 {
		out.JSON = map[string]any{}
		return out, nil
	}
	if errUnmarshal := json.Unmarshal(rawBody, &out.JSON); errUnmarshal != nil {
		return windsurfHTTPResponse{}, fmt.Errorf("parse JSON failed (status %d): %s", resp.StatusCode, string(rawBody))
	}
	return out, nil
}

func windsurfLoginHTTPClient(cfg *config.Config, proxyURL string) (*http.Client, error) {
	effectiveProxy := strings.TrimSpace(proxyURL)
	if effectiveProxy == "" && cfg != nil {
		effectiveProxy = strings.TrimSpace(cfg.ProxyURL)
	}
	client := &http.Client{Timeout: windsurfLoginTimeout}
	if effectiveProxy == "" {
		return client, nil
	}
	transport, _, err := proxyutil.BuildHTTPTransport(effectiveProxy)
	if err != nil {
		return nil, fmt.Errorf("invalid windsurf proxy_url: %w", err)
	}
	if transport != nil {
		client.Transport = transport
	}
	return client, nil
}

func windsurfBuildJSONHeaders(fingerprint map[string]string, body []byte, extra map[string]string) map[string]string {
	headers := make(map[string]string, len(fingerprint)+len(extra)+2)
	for k, v := range fingerprint {
		headers[k] = v
	}
	headers["Content-Type"] = "application/json"
	headers["Content-Length"] = strconv.Itoa(len(body))
	for k, v := range extra {
		headers[k] = v
	}
	return headers
}

func windsurfGenerateFingerprint() map[string]string {
	osVersions := []string{
		"Windows NT 10.0; Win64; x64",
		"Windows NT 10.0; WOW64",
		"Macintosh; Intel Mac OS X 10_15_7",
		"Macintosh; Intel Mac OS X 13_4_1",
		"Macintosh; Intel Mac OS X 14_2_1",
		"X11; Linux x86_64",
		"X11; Ubuntu; Linux x86_64",
	}
	chromeVersions := []string{
		"120.0.0.0", "121.0.0.0", "122.0.0.0", "123.0.0.0", "124.0.0.0",
		"125.0.0.0", "126.0.0.0", "127.0.0.0", "128.0.0.0", "129.0.0.0",
		"130.0.0.0", "131.0.0.0", "132.0.0.0", "133.0.0.0", "134.0.0.0",
	}
	acceptLanguages := []string{
		"en-US,en;q=0.9",
		"en-GB,en;q=0.9",
		"zh-CN,zh;q=0.9,en;q=0.8",
		"zh-TW,zh;q=0.9,en;q=0.8",
		"ja,en-US;q=0.9,en;q=0.8",
		"ko,en-US;q=0.9,en;q=0.8",
	}
	osName := windsurfPick(osVersions)
	chrome := windsurfPick(chromeVersions)
	major := strings.SplitN(chrome, ".", 2)[0]
	platform := `"Linux"`
	if strings.Contains(osName, "Windows") {
		platform = `"Windows"`
	} else if strings.Contains(osName, "Macintosh") {
		platform = `"macOS"`
	}
	ua := fmt.Sprintf("Mozilla/5.0 (%s) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s Safari/537.36", osName, chrome)
	return map[string]string{
		"User-Agent":         ua,
		"Accept-Language":    windsurfPick(acceptLanguages),
		"Accept":             "application/json, text/plain, */*",
		"Accept-Encoding":    "identity",
		"sec-ch-ua":          fmt.Sprintf(`"Chromium";v="%s", "Google Chrome";v="%s", "Not-A.Brand";v="99"`, major, major),
		"sec-ch-ua-mobile":   "?0",
		"sec-ch-ua-platform": platform,
		"Sec-Fetch-Dest":     "empty",
		"Sec-Fetch-Mode":     "cors",
		"Sec-Fetch-Site":     "cross-site",
		"Origin":             "https://windsurf.com",
		"Referer":            "https://windsurf.com/",
	}
}

func windsurfPick(values []string) string {
	if len(values) == 0 {
		return ""
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(values))))
	if err != nil {
		return values[0]
	}
	return values[n.Int64()]
}

func windsurfParsePostAuthResponse(raw []byte) map[string]any {
	rawText := strings.TrimSpace(string(raw))
	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err == nil && parsed != nil {
		if _, ok := parsed["sessionToken"]; ok {
			return parsed
		}
		if token, ok := parsed["session_token"].(string); ok {
			parsed["sessionToken"] = token
		}
		return parsed
	}
	out := make(map[string]any)
	if token := windsurfSessionTokenRE.FindString(rawText); token != "" {
		out["sessionToken"] = token
	}
	if accountID := windsurfAccountIDRE.FindString(rawText); accountID != "" {
		out["accountId"] = accountID
	}
	if orgID := windsurfOrgIDRE.FindString(rawText); orgID != "" {
		out["primaryOrgId"] = orgID
	}
	if len(out) == 0 {
		out["error"] = windsurfTruncate(rawText, 200)
	}
	return out
}

func windsurfQuotaFromUserStatus(data map[string]any) windsurfQuotaResponse {
	status := windsurfMapValue(data, "userStatus")
	planStatus := windsurfMapValue(status, "planStatus")
	planInfo := windsurfMapValue(planStatus, "planInfo")
	if len(planInfo) == 0 {
		planInfo = windsurfMapValue(data, "planInfo")
	}

	return windsurfQuotaResponse{
		PlanName:                    windsurfFirstString(planInfo, "planName", "plan_name"),
		Email:                       windsurfFirstString(status, "email"),
		MonthlyPromptCredits:        windsurfFirstNumber(planInfo, "monthlyPromptCredits", "monthly_prompt_credits"),
		MonthlyFlowCredits:          windsurfFirstNumber(planInfo, "monthlyFlowCredits", "monthly_flow_credits"),
		AvailablePromptCredits:      windsurfFirstNumber(planStatus, "availablePromptCredits", "available_prompt_credits"),
		UsedPromptCredits:           windsurfFirstNumber(planStatus, "usedPromptCredits", "used_prompt_credits"),
		AvailableFlexCredits:        windsurfFirstNumber(planStatus, "availableFlexCredits", "available_flex_credits"),
		DailyQuotaRemainingPercent:  windsurfFirstNumber(planStatus, "dailyQuotaRemainingPercent", "daily_quota_remaining_percent"),
		WeeklyQuotaRemainingPercent: windsurfFirstNumber(planStatus, "weeklyQuotaRemainingPercent", "weekly_quota_remaining_percent"),
		DailyQuotaResetAtUnix:       windsurfFirstString(planStatus, "dailyQuotaResetAtUnix", "daily_quota_reset_at_unix"),
		WeeklyQuotaResetAtUnix:      windsurfFirstString(planStatus, "weeklyQuotaResetAtUnix", "weekly_quota_reset_at_unix"),
		BillingStrategy:             windsurfFirstString(planInfo, "billingStrategy", "billing_strategy"),
		TeamsTier:                   windsurfFirstString(planInfo, "teamsTier", "teams_tier"),
	}
}

func windsurfMapValue(data map[string]any, key string) map[string]any {
	if data == nil {
		return nil
	}
	if value, ok := data[key].(map[string]any); ok {
		return value
	}
	return nil
}

func windsurfFirstString(data map[string]any, keys ...string) string {
	for _, key := range keys {
		if data == nil {
			return ""
		}
		if value, ok := data[key].(string); ok {
			if trimmed := strings.TrimSpace(value); trimmed != "" {
				return trimmed
			}
		}
	}
	return ""
}

func windsurfFirstNumber(data map[string]any, keys ...string) *float64 {
	for _, key := range keys {
		if data == nil {
			return nil
		}
		switch value := data[key].(type) {
		case float64:
			v := value
			return &v
		case int:
			v := float64(value)
			return &v
		case json.Number:
			if parsed, err := value.Float64(); err == nil {
				return &parsed
			}
		case string:
			if parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64); err == nil {
				return &parsed
			}
		}
	}
	return nil
}

func windsurfStringFromMetadata(auth *coreauth.Auth, keys ...string) string {
	if auth == nil {
		return ""
	}
	for _, key := range keys {
		if auth.Metadata != nil {
			if value, ok := auth.Metadata[key].(string); ok {
				if trimmed := strings.TrimSpace(value); trimmed != "" {
					return trimmed
				}
			}
		}
		if auth.Attributes != nil {
			if value := strings.TrimSpace(auth.Attributes[key]); value != "" {
				return value
			}
		}
	}
	return ""
}

func windsurfFriendlyAuthError(prefix, detail, fallback string) *windsurfLoginError {
	normalized := strings.TrimSpace(detail)
	errorCodeMap := map[string]string{
		"EMAIL_NOT_FOUND":           "ERR_EMAIL_NOT_FOUND",
		"INVALID_PASSWORD":          "ERR_INVALID_PASSWORD",
		"INVALID_LOGIN_CREDENTIALS": "ERR_INVALID_CREDENTIALS",
		"Invalid email or password": "ERR_INVALID_CREDENTIALS",
		"No password set. Please log in with Google or GitHub.": "ERR_NO_PASSWORD_SET",
		"No password set":             "ERR_NO_PASSWORD_SET",
		"USER_DISABLED":               "ERR_USER_DISABLED",
		"TOO_MANY_ATTEMPTS_TRY_LATER": "ERR_TOO_MANY_ATTEMPTS",
		"INVALID_EMAIL":               "ERR_INVALID_EMAIL",
	}
	code := errorCodeMap[normalized]
	if code == "" {
		code = normalized
	}
	if code == "" {
		code = fallback
	}
	authFail := normalized == "EMAIL_NOT_FOUND" ||
		normalized == "INVALID_PASSWORD" ||
		normalized == "INVALID_LOGIN_CREDENTIALS" ||
		normalized == "Invalid email or password" ||
		strings.Contains(strings.ToLower(normalized), "password") ||
		strings.Contains(strings.ToLower(normalized), "credential")
	if prefix != "" && !strings.HasPrefix(code, "ERR_") {
		code = prefix + ": " + code
	}
	return &windsurfLoginError{Code: code, StatusCode: http.StatusUnauthorized, IsAuthFail: authFail}
}

func windsurfDetailMessage(value any) string {
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v)
	case []any:
		parts := make([]string, 0, len(v))
		for _, item := range v {
			if m, ok := item.(map[string]any); ok {
				if msg, _ := m["msg"].(string); strings.TrimSpace(msg) != "" {
					parts = append(parts, strings.TrimSpace(msg))
					continue
				}
				if typ, _ := m["type"].(string); strings.TrimSpace(typ) != "" {
					parts = append(parts, strings.TrimSpace(typ))
					continue
				}
			}
			if s := strings.TrimSpace(fmt.Sprint(item)); s != "" {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, "; ")
	default:
		return ""
	}
}

func windsurfShouldCountLoginFailure(err error) bool {
	var loginErr *windsurfLoginError
	if errors.As(err, &loginErr) {
		return loginErr.IsAuthFail
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "password") || strings.Contains(msg, "credential") || strings.Contains(msg, "email")
}

func windsurfEmailLockedFor(email string) time.Duration {
	key := strings.ToLower(strings.TrimSpace(email))
	if key == "" {
		return 0
	}
	now := time.Now()
	windsurfLoginFailures.Lock()
	defer windsurfLoginFailures.Unlock()
	item := windsurfLoginFailures.items[key]
	if item == nil {
		return 0
	}
	if item.LockedUntil.After(now) {
		return time.Until(item.LockedUntil)
	}
	if !item.LockedUntil.IsZero() {
		item.Count = 0
		item.LockedUntil = time.Time{}
	}
	return 0
}

func windsurfRecordLoginFailure(email string, err error) {
	key := strings.ToLower(strings.TrimSpace(email))
	if key == "" {
		return
	}
	now := time.Now()
	windsurfLoginFailures.Lock()
	defer windsurfLoginFailures.Unlock()
	item := windsurfLoginFailures.items[key]
	if item == nil {
		item = &windsurfEmailFailure{}
		windsurfLoginFailures.items[key] = item
	}
	item.Count++
	item.LastActivity = now
	item.LastReason = windsurfTruncate(err.Error(), 80)
	if item.Count >= windsurfEmailLockThreshold {
		item.LockedUntil = now.Add(windsurfEmailLockDuration)
		item.Count = 0
		log.Warnf("windsurf login: locked %s for %s after repeated failures", key, windsurfEmailLockDuration)
	}
}

func windsurfRecordLoginSuccess(email string) {
	key := strings.ToLower(strings.TrimSpace(email))
	if key == "" {
		return
	}
	windsurfLoginFailures.Lock()
	delete(windsurfLoginFailures.items, key)
	windsurfLoginFailures.Unlock()
}

func windsurfPurgeLoginFailures() {
	now := time.Now()
	windsurfLoginFailures.Lock()
	defer windsurfLoginFailures.Unlock()
	for key, item := range windsurfLoginFailures.items {
		if item.LockedUntil.After(now) {
			continue
		}
		if now.Sub(item.LastActivity) > windsurfEmailLockIdleTTL {
			delete(windsurfLoginFailures.items, key)
		}
	}
}

func windsurfAuthMetadataFromLogin(req windsurfLoginRequest, result windsurfLoginResult, proxyURL string) map[string]any {
	metadata := map[string]any{
		"type":        "windsurf",
		"email":       result.Email,
		"api_key":     result.APIKey,
		"transport":   windsurfDefaultTransport(req.Transport),
		"auth_method": result.AuthMethod,
		"last_login":  time.Now().UTC().Format(time.RFC3339),
	}
	if result.Name != "" {
		metadata["name"] = result.Name
	}
	if proxyURL != "" {
		metadata["proxy_url"] = proxyURL
	}
	if result.SessionToken != "" {
		metadata["session_token"] = result.SessionToken
	}
	if result.Auth1Token != "" {
		metadata["auth1_token"] = result.Auth1Token
	}
	if result.AccountID != "" {
		metadata["account_id"] = result.AccountID
	}
	if result.OrgID != "" {
		metadata["primary_org_id"] = result.OrgID
	}
	if result.IDToken != "" {
		metadata["auth_token"] = result.IDToken
		metadata["id_token"] = result.IDToken
	}
	if result.RefreshToken != "" {
		metadata["refresh_token"] = result.RefreshToken
	}
	apiServerURL := strings.TrimSpace(req.APIServerURL)
	if apiServerURL == "" {
		apiServerURL = strings.TrimSpace(result.APIServerURL)
	}
	if apiServerURL != "" {
		metadata["api_server_url"] = apiServerURL
	}
	windsurfCopyOptionalString(metadata, "ls_binary_path", req.LSBinaryPath)
	windsurfCopyOptionalString(metadata, "ls_data_dir", req.LSDataDir)
	windsurfCopyOptionalString(metadata, "workspace_dir", req.WorkspaceDir)
	if v := windsurfStringFromAny(req.LSMaxInstances); v != "" {
		metadata["ls_max_instances"] = v
	}
	if v := windsurfPriorityValue(req.Priority); v != nil {
		metadata["priority"] = v
	}
	if len(req.ExcludedModels) > 0 {
		models := make([]string, 0, len(req.ExcludedModels))
		for _, model := range req.ExcludedModels {
			if trimmed := strings.TrimSpace(model); trimmed != "" {
				models = append(models, trimmed)
			}
		}
		if len(models) > 0 {
			metadata["excluded_models"] = models
		}
	}
	return metadata
}

func windsurfDefaultTransport(value string) string {
	trimmed := strings.TrimSpace(strings.ToLower(value))
	if trimmed == "" {
		return "native"
	}
	return trimmed
}

func windsurfCopyOptionalString(metadata map[string]any, key, value string) {
	if trimmed := strings.TrimSpace(value); trimmed != "" {
		metadata[key] = trimmed
	}
}

func windsurfPriorityValue(value any) any {
	switch v := value.(type) {
	case nil:
		return nil
	case float64:
		return int(v)
	case string:
		if trimmed := strings.TrimSpace(v); trimmed != "" {
			if n, err := strconv.Atoi(trimmed); err == nil {
				return n
			}
			return trimmed
		}
	case json.Number:
		if n, err := strconv.Atoi(v.String()); err == nil {
			return n
		}
		return v.String()
	}
	return value
}

func windsurfProxyURLFromRequest(req windsurfLoginRequest) string {
	if v := strings.TrimSpace(req.ProxyURL); v != "" {
		return v
	}
	if v := strings.TrimSpace(req.ProxyURLDash); v != "" {
		return v
	}
	if len(bytes.TrimSpace(req.Proxy)) == 0 {
		return ""
	}
	var raw any
	if err := json.Unmarshal(req.Proxy, &raw); err != nil {
		return ""
	}
	switch v := raw.(type) {
	case string:
		return strings.TrimSpace(v)
	case map[string]any:
		return windsurfProxyObjectToURL(v)
	default:
		return ""
	}
}

func windsurfProxyObjectToURL(raw map[string]any) string {
	host := strings.TrimSpace(windsurfStringFromAny(raw["host"]))
	if host == "" {
		return ""
	}
	if strings.Contains(host, "://") {
		return host
	}
	scheme := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(windsurfStringFromAny(raw["scheme"]))), ":")
	if scheme == "" {
		scheme = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(windsurfStringFromAny(raw["protocol"]))), ":")
	}
	if scheme == "" {
		scheme = "http"
	}
	port := strings.TrimSpace(windsurfStringFromAny(raw["port"]))
	username := windsurfStringFromAny(raw["username"])
	password := windsurfStringFromAny(raw["password"])
	userInfo := ""
	if username != "" {
		user := url.UserPassword(username, password)
		if password == "" {
			user = url.User(username)
		}
		userInfo = user.String() + "@"
	}
	if port != "" && !strings.Contains(host, ":") {
		host += ":" + port
	}
	return scheme + "://" + userInfo + host
}

func windsurfStringFromAny(value any) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(v)
	case float64:
		if v == float64(int64(v)) {
			return strconv.FormatInt(int64(v), 10)
		}
		return strings.TrimSpace(fmt.Sprintf("%v", v))
	case json.Number:
		return strings.TrimSpace(v.String())
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	default:
		return strings.TrimSpace(fmt.Sprint(v))
	}
}

func windsurfMaskSecret(secret string) string {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return ""
	}
	if len(secret) <= 12 {
		return "****"
	}
	return secret[:8] + "..." + secret[len(secret)-4:]
}

func windsurfJSONSummary(value map[string]any) string {
	if value == nil {
		return ""
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprint(value)
	}
	return windsurfTruncate(string(raw), 200)
}

func windsurfTruncate(value string, limit int) string {
	if limit <= 0 || len(value) <= limit {
		return value
	}
	return value[:limit]
}

func mustJSON(value any) string {
	raw, err := json.Marshal(value)
	if err != nil {
		return "{}"
	}
	return string(raw)
}
