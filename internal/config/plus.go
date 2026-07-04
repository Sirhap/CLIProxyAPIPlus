package config

// PlusConfig holds configuration fields that are fork-only (not present in
// upstream router-for-me/CLIProxyAPI). Kept in a separate file and embedded
// into Config via `yaml:",inline"` (see config.go) so upstream syncs never
// have to merge fork-only fields against upstream's own Config field
// additions. These fields were previously inline in Config and were lost
// once during a sync (see commit b888d19e) before being manually restored —
// this isolation prevents a repeat.
type PlusConfig struct {
	// KiroKey defines a list of Kiro (AWS CodeWhisperer) configurations.
	KiroKey []KiroKey `yaml:"kiro" json:"kiro"`

	// KiroFingerprint defines a global fingerprint configuration for all Kiro requests.
	// When set, all Kiro requests will use this fixed fingerprint instead of random generation.
	KiroFingerprint *KiroFingerprintConfig `yaml:"kiro-fingerprint,omitempty" json:"kiro-fingerprint,omitempty"`

	// KiroPreferredEndpoint sets the global default preferred endpoint for all Kiro providers.
	// Values: "ide" (default, CodeWhisperer) or "cli" (Amazon Q).
	KiroPreferredEndpoint string `yaml:"kiro-preferred-endpoint" json:"kiro-preferred-endpoint"`

	// KiroRateLimit configures rate limiting parameters for Kiro requests.
	// When nil, default values are used.
	KiroRateLimit *KiroRateLimitConfig `yaml:"kiro-rate-limit,omitempty" json:"kiro-rate-limit,omitempty"`

	// KiroSystemPromptInjectEnable controls whether system prompts are injected
	// into Kiro user messages (wrapped with --- SYSTEM PROMPT --- markers).
	// When nil or false (default), system prompts are dropped — Kiro API will
	// not see any system instructions. Set to true to enable injection.
	KiroSystemPromptInjectEnable *bool `yaml:"kiro-system-prompt-inject-enable,omitempty" json:"kiro-system-prompt-inject-enable,omitempty"`

	// KiroTruncationDetectorEnable controls whether the heuristic truncation detector
	// is applied to Kiro tool use responses. When enabled, tool calls that appear
	// truncated (invalid JSON, missing required fields, etc.) are silently skipped.
	// Default: false (disabled). The detector uses heuristic matching that can produce
	// false positives, so it is off by default.
	KiroTruncationDetectorEnable *bool `yaml:"kiro-truncation-detector-enable,omitempty" json:"kiro-truncation-detector-enable,omitempty"`

	// KiroExtractThinkingTagEnable controls whether inline <thinking>...</thinking>
	// tags in Kiro assistantResponseEvent content are parsed into Claude thinking
	// content blocks. Kiro's official reasoning channel is reasoningContentEvent;
	// the tag-based path is unofficial and can false-positive when content literally
	// contains the tag string (code samples, discussion, XML fixtures), silently
	// truncating responses. Default: false (disabled).
	KiroExtractThinkingTagEnable *bool `yaml:"kiro-extract-thinking-tag-enable,omitempty" json:"kiro-extract-thinking-tag-enable,omitempty"`
}

// KiroKey represents the configuration for Kiro (AWS CodeWhisperer) authentication.
type KiroKey struct {
	// TokenFile is the path to the Kiro token file (default: ~/.aws/sso/cache/kiro-auth-token.json)
	TokenFile string `yaml:"token-file,omitempty" json:"token-file,omitempty"`

	// AccessToken is the OAuth access token for direct configuration.
	AccessToken string `yaml:"access-token,omitempty" json:"access-token,omitempty"`

	// RefreshToken is the OAuth refresh token for token renewal.
	RefreshToken string `yaml:"refresh-token,omitempty" json:"refresh-token,omitempty"`

	// ProfileArn is the AWS CodeWhisperer profile ARN.
	ProfileArn string `yaml:"profile-arn,omitempty" json:"profile-arn,omitempty"`

	// Region is the AWS region (default: us-east-1).
	Region string `yaml:"region,omitempty" json:"region,omitempty"`

	// StartURL is the IAM Identity Center (IDC) start URL for SSO login.
	StartURL string `yaml:"start-url,omitempty" json:"start-url,omitempty"`

	// ProxyURL optionally overrides the global proxy for this configuration.
	ProxyURL string `yaml:"proxy-url,omitempty" json:"proxy-url,omitempty"`

	// AgentTaskType sets the Kiro API task type. Known values: "vibe", "dev", "chat".
	// Leave empty to let API use defaults. Different values may inject different system prompts.
	AgentTaskType string `yaml:"agent-task-type,omitempty" json:"agent-task-type,omitempty"`

	// PreferredEndpoint sets the preferred Kiro API endpoint/quota.
	// Values: "codewhisperer" (default, IDE quota) or "amazonq" (CLI quota).
	PreferredEndpoint string `yaml:"preferred-endpoint,omitempty" json:"preferred-endpoint,omitempty"`
}

// KiroFingerprintConfig defines a global fingerprint configuration for Kiro requests.
// When configured, all Kiro requests will use this fixed fingerprint instead of random generation.
// Empty fields will fall back to random selection from built-in pools.
type KiroFingerprintConfig struct {
	OIDCSDKVersion      string `yaml:"oidc-sdk-version,omitempty" json:"oidc-sdk-version,omitempty"`
	RuntimeSDKVersion   string `yaml:"runtime-sdk-version,omitempty" json:"runtime-sdk-version,omitempty"`
	StreamingSDKVersion string `yaml:"streaming-sdk-version,omitempty" json:"streaming-sdk-version,omitempty"`
	OSType              string `yaml:"os-type,omitempty" json:"os-type,omitempty"`
	OSVersion           string `yaml:"os-version,omitempty" json:"os-version,omitempty"`
	NodeVersion         string `yaml:"node-version,omitempty" json:"node-version,omitempty"`
	KiroVersion         string `yaml:"kiro-version,omitempty" json:"kiro-version,omitempty"`
	KiroHash            string `yaml:"kiro-hash,omitempty" json:"kiro-hash,omitempty"`
}

// KiroRateLimitConfig defines rate limiting parameters for Kiro requests.
// All duration fields accept Go duration strings (e.g., "1s", "30s", "5m").
// Zero or negative values use defaults.
type KiroRateLimitConfig struct {
	// Enabled controls whether rate limiting is active (default: false).
	// Set to true to enable rate limiting for Kiro requests.
	Enabled *bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	// MinTokenInterval is the minimum interval between requests (default: 1s).
	MinTokenInterval string `yaml:"min-token-interval,omitempty" json:"min-token-interval,omitempty"`
	// MaxTokenInterval is the maximum interval between requests (default: 2s).
	MaxTokenInterval string `yaml:"max-token-interval,omitempty" json:"max-token-interval,omitempty"`
	// DailyMaxRequests is the maximum requests per token per day (default: 500).
	DailyMaxRequests int `yaml:"daily-max-requests,omitempty" json:"daily-max-requests,omitempty"`
	// JitterPercent is the random jitter percentage for intervals (default: 0.3).
	JitterPercent float64 `yaml:"jitter-percent,omitempty" json:"jitter-percent,omitempty"`
	// BackoffBase is the base duration for exponential backoff (default: 30s).
	BackoffBase string `yaml:"backoff-base,omitempty" json:"backoff-base,omitempty"`
	// BackoffMax is the maximum backoff duration (default: 5m).
	BackoffMax string `yaml:"backoff-max,omitempty" json:"backoff-max,omitempty"`
	// BackoffMultiplier is the multiplier for exponential backoff (default: 1.5).
	BackoffMultiplier float64 `yaml:"backoff-multiplier,omitempty" json:"backoff-multiplier,omitempty"`
	// SuspendCooldown is the cooldown duration after suspension detection (default: 1h).
	SuspendCooldown string `yaml:"suspend-cooldown,omitempty" json:"suspend-cooldown,omitempty"`
}
