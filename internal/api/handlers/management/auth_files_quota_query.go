package management

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	kiroauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/kiro"
	vertexauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/vertex"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v7/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var (
	copilotInternalUserURL = "https://api.github.com/copilot_internal/user"
	cloudQuotasAPIBaseURL  = "https://cloudquotas.googleapis.com/v1"
	openAIUsageAPIURL      = "https://api.openai.com/v1/organization/usage/completions"
)

type authFileQuotaQueryRequest struct {
	Name           string `json:"name"`
	AuthIndexSnake string `json:"auth_index"`
	AuthIndexCamel string `json:"authIndex"`
	Provider       string `json:"provider"`
}

type providerQuotaMetric struct {
	ID               string   `json:"id"`
	Label            string   `json:"label,omitempty"`
	Used             *float64 `json:"used,omitempty"`
	Limit            *float64 `json:"limit,omitempty"`
	Remaining        *float64 `json:"remaining,omitempty"`
	RemainingPercent *float64 `json:"remaining_percent,omitempty"`
	ResetAt          string   `json:"reset_at,omitempty"`
	Unit             string   `json:"unit,omitempty"`
}

type providerQuotaResponse struct {
	Status              string                `json:"status"`
	Provider            string                `json:"provider"`
	Source              string                `json:"source,omitempty"`
	Metrics             []providerQuotaMetric `json:"metrics,omitempty"`
	ResetAt             string                `json:"reset_at,omitempty"`
	RawSupported        bool                  `json:"raw_supported"`
	UnavailableReason   string                `json:"unavailable_reason,omitempty"`
	Plan                string                `json:"plan,omitempty"`
	Account             string                `json:"account,omitempty"`
	DocumentationSource string                `json:"documentation_source,omitempty"`
}

// GetAuthFileQuotaQuery returns real upstream quota/usage data when a stable source exists.
// Unsupported providers return status=unsupported instead of fabricated quota numbers.
func (h *Handler) GetAuthFileQuotaQuery(c *gin.Context) {
	var req authFileQuotaQueryRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}

	auth := h.findQuotaQueryAuth(req)
	if auth == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "auth file not found"})
		return
	}

	provider := quotaProvider(req.Provider, auth)
	var (
		resp providerQuotaResponse
		err  error
	)

	switch provider {
	case "github-copilot", "copilot", "github":
		resp, err = h.queryCopilotQuota(c.Request.Context(), auth)
	case "kiro":
		resp, err = h.queryKiroQuota(c.Request.Context(), auth)
	case "vertex":
		resp, err = h.queryVertexQuota(c.Request.Context(), auth)
	case "openai", "openai-api", "openai-compatibility", "openai-compatible":
		resp, err = h.queryOpenAIUsage(c.Request.Context(), auth)
	default:
		resp = unsupportedQuota(provider, unsupportedQuotaReason(provider))
	}

	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

func (h *Handler) findQuotaQueryAuth(req authFileQuotaQueryRequest) *coreauth.Auth {
	if h == nil {
		return nil
	}
	if name := strings.TrimSpace(req.Name); name != "" {
		if auth := h.findManagedAuthByName(name); auth != nil {
			return auth
		}
	}
	authIndex := strings.TrimSpace(req.AuthIndexSnake)
	if authIndex == "" {
		authIndex = strings.TrimSpace(req.AuthIndexCamel)
	}
	return h.authByIndex(authIndex)
}

func quotaProvider(requested string, auth *coreauth.Auth) string {
	if v := strings.ToLower(strings.TrimSpace(requested)); v != "" {
		return v
	}
	if auth == nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(auth.Provider))
}

func unsupportedQuota(provider, reason string) providerQuotaResponse {
	return providerQuotaResponse{
		Status:            "unsupported",
		Provider:          provider,
		RawSupported:      false,
		UnavailableReason: reason,
	}
}

func unsupportedQuotaReason(provider string) string {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "gemini", "aistudio":
		return "API key credentials do not expose a stable per-account remaining quota endpoint."
	case "codebuddy":
		return "No stable public CodeBuddy quota endpoint is available."
	case "cursor":
		return "Cursor exposes request usage in responses, but no stable account quota endpoint is available."
	case "kilo":
		return "Kilo exposes model and chat endpoints, but no stable account quota endpoint is available."
	case "gitlab":
		return "GitLab Duo request usage is not the same as account remaining quota."
	case "xai":
		return "No stable xAI remaining quota endpoint is confirmed."
	case "openai-compatibility", "openai-compatible":
		return "OpenAI-compatible providers do not share a standard quota API."
	default:
		return "This provider has no stable real quota source configured."
	}
}

func (h *Handler) queryCopilotQuota(ctx context.Context, auth *coreauth.Auth) (providerQuotaResponse, error) {
	usage, err := h.fetchCopilotUsage(ctx, auth)
	if err != nil {
		return providerQuotaResponse{}, err
	}
	metrics := copilotQuotaMetrics(usage)
	return providerQuotaResponse{
		Status:       "success",
		Provider:     "github-copilot",
		Source:       copilotInternalUserURL,
		Metrics:      metrics,
		ResetAt:      strings.TrimSpace(usage.QuotaResetDate),
		RawSupported: true,
		Plan:         strings.TrimSpace(usage.CopilotPlan),
	}, nil
}

func (h *Handler) fetchCopilotUsage(ctx context.Context, auth *coreauth.Auth) (*CopilotUsageResponse, error) {
	if auth == nil {
		return nil, fmt.Errorf("no github copilot credential found")
	}
	token, tokenErr := h.resolveTokenForAuth(ctx, auth)
	if tokenErr != nil {
		return nil, fmt.Errorf("failed to refresh copilot token: %w", tokenErr)
	}
	if token == "" {
		return nil, fmt.Errorf("copilot token not found")
	}

	req, errNewRequest := http.NewRequestWithContext(ctx, http.MethodGet, copilotInternalUserURL, nil)
	if errNewRequest != nil {
		return nil, fmt.Errorf("failed to build request: %w", errNewRequest)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "CLIProxyAPIPlus")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: defaultAPICallTimeout, Transport: h.apiCallTransport(auth)}
	resp, errDo := client.Do(req)
	if errDo != nil {
		return nil, fmt.Errorf("request failed: %w", errDo)
	}
	defer resp.Body.Close()

	respBody, errReadAll := io.ReadAll(resp.Body)
	if errReadAll != nil {
		return nil, fmt.Errorf("failed to read response: %w", errReadAll)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github api request failed (status %d): %s", resp.StatusCode, string(respBody))
	}

	var usage CopilotUsageResponse
	if errUnmarshal := json.Unmarshal(respBody, &usage); errUnmarshal != nil {
		return nil, fmt.Errorf("failed to parse response: %w", errUnmarshal)
	}
	return &usage, nil
}

func copilotQuotaMetrics(usage *CopilotUsageResponse) []providerQuotaMetric {
	if usage == nil {
		return nil
	}
	snapshots := []QuotaDetail{
		usage.QuotaSnapshots.Chat,
		usage.QuotaSnapshots.Completions,
		usage.QuotaSnapshots.PremiumInteractions,
	}
	labels := []string{"Chat", "Completions", "Premium interactions"}
	metrics := make([]providerQuotaMetric, 0, len(snapshots))
	for i, detail := range snapshots {
		id := strings.TrimSpace(detail.QuotaID)
		if id == "" {
			id = strings.ToLower(strings.ReplaceAll(labels[i], " ", "_"))
		}
		limit := detail.Entitlement
		remaining := detail.QuotaRemaining
		if remaining == 0 && detail.Remaining != 0 {
			remaining = detail.Remaining
		}
		var used *float64
		if limit > 0 {
			v := limit - remaining
			if v < 0 {
				v = 0
			}
			used = &v
		}
		var limitPtr *float64
		if limit > 0 {
			limitPtr = &limit
		}
		var remainingPtr *float64
		if remaining != 0 || limit > 0 {
			remainingPtr = &remaining
		}
		percent := detail.PercentRemaining
		if percent == 0 && limit > 0 {
			percent = (remaining / limit) * 100
		}
		var percentPtr *float64
		if percent != 0 || limit > 0 {
			percentPtr = &percent
		}
		metrics = append(metrics, providerQuotaMetric{
			ID:               id,
			Label:            labels[i],
			Used:             used,
			Limit:            limitPtr,
			Remaining:        remainingPtr,
			RemainingPercent: percentPtr,
			Unit:             "requests",
		})
	}
	return metrics
}

func (h *Handler) queryKiroQuota(ctx context.Context, auth *coreauth.Auth) (providerQuotaResponse, error) {
	tokenData, errToken := h.kiroTokenData(ctx, auth)
	if errToken != nil {
		return providerQuotaResponse{}, errToken
	}
	client := kiroauth.NewCodeWhispererClient(h.cfg, "")
	usage, errUsage := client.GetUsageLimits(ctx, tokenData.AccessToken, tokenData.ClientID, tokenData.RefreshToken, tokenData.ProfileArn)
	if errUsage != nil {
		return providerQuotaResponse{}, errUsage
	}
	return normalizeKiroQuotaResponse(usage), nil
}

func (h *Handler) kiroTokenData(ctx context.Context, auth *coreauth.Auth) (*kiroauth.KiroTokenData, error) {
	if auth == nil || auth.Metadata == nil {
		return nil, fmt.Errorf("kiro credential not found")
	}
	meta := auth.Metadata
	tokenData := &kiroauth.KiroTokenData{
		AccessToken:  stringValue(meta, "access_token"),
		RefreshToken: stringValue(meta, "refresh_token"),
		ProfileArn:   stringValue(meta, "profile_arn"),
		ExpiresAt:    stringValue(meta, "expires_at"),
		AuthMethod:   stringValue(meta, "auth_method"),
		Provider:     stringValue(meta, "provider"),
		ClientID:     stringValue(meta, "client_id"),
		ClientSecret: stringValue(meta, "client_secret"),
		ClientIDHash: stringValue(meta, "client_id_hash"),
		Region:       stringValue(meta, "region"),
		StartURL:     stringValue(meta, "start_url"),
		Email:        stringValue(meta, "email"),
	}
	if tokenData.AccessToken == "" {
		return nil, fmt.Errorf("kiro credential missing access token")
	}
	if shouldRefreshKiroToken(tokenData.ExpiresAt) && tokenData.RefreshToken != "" {
		updated, errRefresh := sdkAuth.NewKiroAuthenticator().Refresh(ctx, h.cfg, auth)
		if errRefresh == nil && updated != nil {
			if h.authManager != nil {
				_, _ = h.authManager.Update(ctx, updated)
			}
			return h.kiroTokenData(ctx, updated)
		}
	}
	return tokenData, nil
}

func shouldRefreshKiroToken(expiresAt string) bool {
	expiresAt = strings.TrimSpace(expiresAt)
	if expiresAt == "" {
		return false
	}
	ts, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		return false
	}
	return time.Until(ts) < 5*time.Minute
}

func normalizeKiroQuotaResponse(usage *kiroauth.UsageLimitsResponse) providerQuotaResponse {
	resp := providerQuotaResponse{
		Status:              "success",
		Provider:            "kiro",
		Source:              "codewhisperer:GetUsageLimits",
		RawSupported:        true,
		DocumentationSource: "AWS CodeWhisperer getUsageLimits",
	}
	if usage == nil {
		resp.Status = "unsupported"
		resp.RawSupported = false
		resp.UnavailableReason = "Kiro usage response was empty."
		return resp
	}
	if usage.UserInfo != nil {
		resp.Account = usage.UserInfo.Email
	}
	if usage.SubscriptionInfo != nil {
		resp.Plan = strings.TrimSpace(usage.SubscriptionInfo.SubscriptionTitle)
		if resp.Plan == "" {
			resp.Plan = strings.TrimSpace(usage.SubscriptionInfo.Type)
		}
	}
	if usage.NextDateReset != nil && *usage.NextDateReset > 0 {
		resp.ResetAt = time.Unix(int64(*usage.NextDateReset/1000), 0).UTC().Format(time.RFC3339)
	}
	for _, breakdown := range usage.UsageBreakdownList {
		limit := firstFloatPtr(breakdown.UsageLimitWithPrecision, intPtrToFloatPtr(breakdown.UsageLimit))
		used := firstFloatPtr(breakdown.CurrentUsageWithPrecision, intPtrToFloatPtr(breakdown.CurrentUsage))
		metric := providerQuotaMetric{
			ID:    firstNonEmptyStringValue(breakdown.ResourceType, breakdown.DisplayName, "usage"),
			Label: firstNonEmptyStringValue(breakdown.DisplayName, breakdown.ResourceType, "Usage"),
			Unit:  "requests",
		}
		if limit != nil {
			metric.Limit = limit
		}
		if used != nil {
			metric.Used = used
		}
		if limit != nil && used != nil {
			remaining := *limit - *used
			if remaining < 0 {
				remaining = 0
			}
			metric.Remaining = &remaining
			if *limit > 0 {
				percent := (remaining / *limit) * 100
				metric.RemainingPercent = &percent
			}
		}
		if breakdown.NextDateReset != nil && *breakdown.NextDateReset > 0 {
			metric.ResetAt = time.Unix(int64(*breakdown.NextDateReset/1000), 0).UTC().Format(time.RFC3339)
		} else {
			metric.ResetAt = resp.ResetAt
		}
		resp.Metrics = append(resp.Metrics, metric)
	}
	return resp
}

func (h *Handler) queryVertexQuota(ctx context.Context, auth *coreauth.Auth) (providerQuotaResponse, error) {
	projectID := strings.TrimSpace(stringValue(auth.Metadata, "project_id"))
	if projectID == "" && auth.Attributes != nil {
		projectID = strings.TrimSpace(auth.Attributes["project_id"])
	}
	if projectID == "" {
		return unsupportedQuota("vertex", "Vertex credential is missing project_id."), nil
	}

	token, errToken := h.vertexCloudAccessToken(ctx, auth)
	if errToken != nil {
		return providerQuotaResponse{}, errToken
	}

	apiURL := fmt.Sprintf("%s/projects/%s/locations/global/services/aiplatform.googleapis.com/quotaInfos?pageSize=200", strings.TrimRight(cloudQuotasAPIBaseURL, "/"), url.PathEscape(projectID))
	req, errReq := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if errReq != nil {
		return providerQuotaResponse{}, errReq
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	client := &http.Client{Timeout: defaultAPICallTimeout, Transport: h.apiCallTransport(auth)}
	resp, errDo := client.Do(req)
	if errDo != nil {
		return providerQuotaResponse{}, errDo
	}
	defer resp.Body.Close()
	body, errRead := io.ReadAll(resp.Body)
	if errRead != nil {
		return providerQuotaResponse{}, errRead
	}
	if resp.StatusCode != http.StatusOK {
		return providerQuotaResponse{}, fmt.Errorf("cloud quotas request failed (status %d): %s", resp.StatusCode, string(body))
	}
	metrics := parseCloudQuotaMetrics(body)
	return providerQuotaResponse{
		Status:       "success",
		Provider:     "vertex",
		Source:       "cloudquotas.googleapis.com",
		Metrics:      metrics,
		RawSupported: true,
		Account:      projectID,
	}, nil
}

func (h *Handler) vertexCloudAccessToken(ctx context.Context, auth *coreauth.Auth) (string, error) {
	if auth == nil || auth.Metadata == nil {
		return "", fmt.Errorf("vertex credential not found")
	}
	raw, ok := auth.Metadata["service_account"].(map[string]any)
	if !ok || raw == nil {
		return "", fmt.Errorf("vertex credential missing service_account")
	}
	normalized, errNorm := vertexauth.NormalizeServiceAccountMap(raw)
	if errNorm != nil {
		return "", errNorm
	}
	saJSON, errMarshal := json.Marshal(normalized)
	if errMarshal != nil {
		return "", errMarshal
	}
	httpClient := &http.Client{Timeout: defaultAPICallTimeout, Transport: h.apiCallTransport(auth)}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)
	creds, errCreds := google.CredentialsFromJSON(ctx, saJSON, "https://www.googleapis.com/auth/cloud-platform")
	if errCreds != nil {
		return "", errCreds
	}
	token, errAccess := creds.TokenSource.Token()
	if errAccess != nil {
		return "", errAccess
	}
	return strings.TrimSpace(token.AccessToken), nil
}

func parseCloudQuotaMetrics(body []byte) []providerQuotaMetric {
	var raw struct {
		QuotaInfos []struct {
			Name            string `json:"name"`
			QuotaID         string `json:"quotaId"`
			Metric          string `json:"metric"`
			DisplayName     string `json:"displayName"`
			QuotaValue      any    `json:"quotaValue"`
			RefreshInterval string `json:"refreshInterval"`
		} `json:"quotaInfos"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil
	}
	metrics := make([]providerQuotaMetric, 0, len(raw.QuotaInfos))
	for _, info := range raw.QuotaInfos {
		limit, ok := numberFromAny(info.QuotaValue)
		if !ok {
			continue
		}
		metrics = append(metrics, providerQuotaMetric{
			ID:    firstNonEmptyStringValue(info.QuotaID, info.Metric, info.Name),
			Label: firstNonEmptyStringValue(info.DisplayName, info.Metric, info.QuotaID),
			Limit: &limit,
			Unit:  "quota",
		})
	}
	return metrics
}

func (h *Handler) queryOpenAIUsage(ctx context.Context, auth *coreauth.Auth) (providerQuotaResponse, error) {
	if !isOfficialOpenAIAuth(auth) {
		return unsupportedQuota("openai-compatibility", unsupportedQuotaReason("openai-compatibility")), nil
	}
	token := tokenValueForAuth(auth)
	if token == "" {
		return providerQuotaResponse{}, fmt.Errorf("openai api key not found")
	}
	startTime := time.Now().UTC().AddDate(0, 0, -7).Unix()
	apiURL := fmt.Sprintf("%s?start_time=%d&bucket_width=1d&limit=7", openAIUsageAPIURL, startTime)
	req, errReq := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if errReq != nil {
		return providerQuotaResponse{}, errReq
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: defaultAPICallTimeout, Transport: h.apiCallTransport(auth)}
	resp, errDo := client.Do(req)
	if errDo != nil {
		return providerQuotaResponse{}, errDo
	}
	defer resp.Body.Close()
	body, errRead := io.ReadAll(resp.Body)
	if errRead != nil {
		return providerQuotaResponse{}, errRead
	}
	if resp.StatusCode != http.StatusOK {
		return providerQuotaResponse{}, fmt.Errorf("openai usage request failed (status %d): %s", resp.StatusCode, string(body))
	}
	return providerQuotaResponse{
		Status:       "success",
		Provider:     "openai",
		Source:       openAIUsageAPIURL,
		Metrics:      parseOpenAIUsageMetrics(body),
		RawSupported: true,
	}, nil
}

func isOfficialOpenAIAuth(auth *coreauth.Auth) bool {
	if auth == nil {
		return false
	}
	provider := strings.ToLower(strings.TrimSpace(auth.Provider))
	baseURL := ""
	if auth.Attributes != nil {
		baseURL = strings.TrimSpace(auth.Attributes["base_url"])
	}
	if provider == "openai" {
		return baseURL == "" || strings.Contains(strings.ToLower(baseURL), "api.openai.com")
	}
	if provider == "openai-compatibility" || provider == "openai-compatible" {
		return strings.Contains(strings.ToLower(baseURL), "api.openai.com")
	}
	return false
}

func parseOpenAIUsageMetrics(body []byte) []providerQuotaMetric {
	var raw struct {
		Data []struct {
			Results []struct {
				InputTokens      float64 `json:"input_tokens"`
				OutputTokens     float64 `json:"output_tokens"`
				NumModelRequests float64 `json:"num_model_requests"`
			} `json:"results"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil
	}
	var inputTokens, outputTokens, requests float64
	for _, bucket := range raw.Data {
		for _, result := range bucket.Results {
			inputTokens += result.InputTokens
			outputTokens += result.OutputTokens
			requests += result.NumModelRequests
		}
	}
	return []providerQuotaMetric{
		{ID: "input_tokens_7d", Label: "Input tokens (7d)", Used: &inputTokens, Unit: "tokens"},
		{ID: "output_tokens_7d", Label: "Output tokens (7d)", Used: &outputTokens, Unit: "tokens"},
		{ID: "requests_7d", Label: "Requests (7d)", Used: &requests, Unit: "requests"},
	}
}

func firstFloatPtr(values ...*float64) *float64 {
	for _, value := range values {
		if value != nil {
			return value
		}
	}
	return nil
}

func intPtrToFloatPtr(value *int) *float64 {
	if value == nil {
		return nil
	}
	converted := float64(*value)
	return &converted
}

func firstNonEmptyStringValue(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func numberFromAny(value any) (float64, bool) {
	switch typed := value.(type) {
	case float64:
		return typed, true
	case int:
		return float64(typed), true
	case string:
		trimmed := strings.TrimSpace(typed)
		if trimmed == "" {
			return 0, false
		}
		var parsed float64
		if _, err := fmt.Sscanf(trimmed, "%f", &parsed); err == nil {
			return parsed, true
		}
	}
	return 0, false
}
