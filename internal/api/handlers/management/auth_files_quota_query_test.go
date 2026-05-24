package management

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/auth/kiro"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestAuthFileQuotaQueryCopilotFetchesRealShape(t *testing.T) {
	prevURL := copilotInternalUserURL
	defer func() { copilotInternalUserURL = prevURL }()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer copilot-token" {
			t.Fatalf("Authorization = %q, want bearer token", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"copilot_plan":"business",
			"quota_reset_date":"2026-06-01T00:00:00Z",
			"quota_snapshots":{
				"chat":{"quota_id":"chat","entitlement":100,"quota_remaining":80,"percent_remaining":80},
				"completions":{"quota_id":"completions","entitlement":50,"remaining":25},
				"premium_interactions":{"quota_id":"premium_interactions","unlimited":true}
			}
		}`))
	}))
	defer upstream.Close()
	copilotInternalUserURL = upstream.URL

	manager := coreauth.NewManager(nil, nil, nil)
	auth := &coreauth.Auth{
		ID:       "copilot.json",
		Provider: "github-copilot",
		FileName: "copilot.json",
		Metadata: map[string]any{"access_token": "copilot-token"},
	}
	if _, err := manager.Register(context.Background(), auth); err != nil {
		t.Fatalf("Register returned error: %v", err)
	}

	h := NewHandler(&config.Config{}, "", manager)
	router := gin.New()
	router.POST("/quota", h.GetAuthFileQuotaQuery)

	body := bytes.NewBufferString(`{"name":"copilot.json"}`)
	req := httptest.NewRequest(http.MethodPost, "/quota", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var got providerQuotaResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}
	if got.Provider != "github-copilot" || got.Status != "success" || !got.RawSupported {
		t.Fatalf("response = %#v", got)
	}
	if len(got.Metrics) != 3 {
		t.Fatalf("metrics len = %d, want 3", len(got.Metrics))
	}
	if got.Metrics[0].Remaining == nil || *got.Metrics[0].Remaining != 80 {
		t.Fatalf("chat remaining = %#v, want 80", got.Metrics[0].Remaining)
	}
}

func TestAuthFileQuotaQueryUnsupportedProviderIsExplicit(t *testing.T) {
	manager := coreauth.NewManager(nil, nil, nil)
	auth := &coreauth.Auth{ID: "cursor.json", Provider: "cursor", FileName: "cursor.json"}
	if _, err := manager.Register(context.Background(), auth); err != nil {
		t.Fatalf("Register returned error: %v", err)
	}

	h := NewHandler(&config.Config{}, "", manager)
	router := gin.New()
	router.POST("/quota", h.GetAuthFileQuotaQuery)

	req := httptest.NewRequest(http.MethodPost, "/quota", bytes.NewBufferString(`{"name":"cursor.json"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var got providerQuotaResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}
	if got.Status != "unsupported" || got.RawSupported || got.UnavailableReason == "" {
		t.Fatalf("response = %#v", got)
	}
}

func TestNormalizeKiroQuotaResponse(t *testing.T) {
	limit := 100.0
	used := 35.0
	reset := float64(1764547200000)
	got := normalizeKiroQuotaResponse(&kiro.UsageLimitsResponse{
		NextDateReset: &reset,
		UserInfo:      &kiro.UserInfo{Email: "user@example.com"},
		SubscriptionInfo: &kiro.SubscriptionInfo{
			SubscriptionTitle: "Kiro Pro",
		},
		UsageBreakdownList: []kiro.UsageBreakdown{{
			ResourceType:              "AGENTIC_REQUEST",
			DisplayName:               "Agentic requests",
			UsageLimitWithPrecision:   &limit,
			CurrentUsageWithPrecision: &used,
		}},
	})

	if got.Status != "success" || got.Provider != "kiro" || got.Account != "user@example.com" || got.Plan != "Kiro Pro" {
		t.Fatalf("response = %#v", got)
	}
	if len(got.Metrics) != 1 {
		t.Fatalf("metrics len = %d, want 1", len(got.Metrics))
	}
	if got.Metrics[0].Remaining == nil || *got.Metrics[0].Remaining != 65 {
		t.Fatalf("remaining = %#v, want 65", got.Metrics[0].Remaining)
	}
}

func TestParseOpenAIUsageMetrics(t *testing.T) {
	metrics := parseOpenAIUsageMetrics([]byte(`{
		"data":[
			{"results":[{"input_tokens":10,"output_tokens":5,"num_model_requests":2}]},
			{"results":[{"input_tokens":7,"output_tokens":3,"num_model_requests":1}]}
		]
	}`))
	if len(metrics) != 3 {
		t.Fatalf("metrics len = %d, want 3", len(metrics))
	}
	if metrics[0].Used == nil || *metrics[0].Used != 17 {
		t.Fatalf("input tokens = %#v, want 17", metrics[0].Used)
	}
}
