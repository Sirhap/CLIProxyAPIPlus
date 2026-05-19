package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/thinking"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/usage"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// WindsurfClient mirrors WindsurfAPI's src/client.js boundary. It owns the
// native Language Server flow: workspace/panel initialization, Cascade start,
// message send, trajectory polling, and response shaping.
type WindsurfClient struct {
	cfg    *config.Config
	lsPool *WindsurfLanguageServerPool
}

func NewWindsurfClient(cfg *config.Config) *WindsurfClient {
	return &WindsurfClient{
		cfg:    cfg,
		lsPool: NewWindsurfLanguageServerPool(cfg),
	}
}

func (c *WindsurfClient) ChatCompletions(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	run, err := c.startCascade(ctx, auth, req, opts)
	if err != nil {
		return cliproxyexecutor.Response{}, err
	}
	result, err := c.pollCascade(ctx, run, nil)
	if err != nil {
		return cliproxyexecutor.Response{}, err
	}
	body := buildWindsurfOpenAIResponse(run, result)
	reporter := helps.NewUsageReporter(ctx, windsurfProvider, run.Model, auth)
	reporter.Publish(ctx, windsurfUsageDetail(result.Usage))
	reporter.EnsurePublished(ctx)
	var param any
	out := sdktranslator.TranslateNonStream(ctx, sdktranslator.FromString("openai"), opts.SourceFormat, req.Model, opts.OriginalRequest, run.TranslatedRequest, body, &param)
	return cliproxyexecutor.Response{
		Payload: out,
		Headers: http.Header{"Content-Type": []string{"application/json"}},
	}, nil
}

func (c *WindsurfClient) ChatCompletionsStream(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	run, err := c.startCascade(ctx, auth, req, opts)
	if err != nil {
		return nil, err
	}
	out := make(chan cliproxyexecutor.StreamChunk)
	go func() {
		defer close(out)
		reporter := helps.NewUsageReporter(ctx, windsurfProvider, run.Model, auth)
		var param any
		emit := func(line []byte) bool {
			chunks := sdktranslator.TranslateStream(ctx, sdktranslator.FromString("openai"), opts.SourceFormat, req.Model, opts.OriginalRequest, run.TranslatedRequest, line, &param)
			for _, chunk := range chunks {
				select {
				case out <- cliproxyexecutor.StreamChunk{Payload: chunk}:
				case <-ctx.Done():
					return false
				}
			}
			return true
		}
		_ = emit(windsurfOpenAIStreamRoleChunk(run, "assistant"))
		result, errPoll := c.pollCascade(ctx, run, func(delta string) bool {
			if delta == "" {
				return true
			}
			return emit(windsurfOpenAIStreamContentChunk(run, delta))
		})
		if errPoll != nil {
			reporter.PublishFailure(ctx, errPoll)
			select {
			case out <- cliproxyexecutor.StreamChunk{Err: errPoll}:
			case <-ctx.Done():
			}
			return
		}
		if len(result.ToolCalls) > 0 {
			if !emit(windsurfOpenAIStreamToolCallChunk(run, result.ToolCalls)) {
				return
			}
		}
		if !emit(windsurfOpenAIStreamFinishChunk(run, result.FinishReason)) {
			return
		}
		reporter.Publish(ctx, windsurfUsageDetail(result.Usage))
		reporter.EnsurePublished(ctx)
		_ = emit([]byte("data: [DONE]"))
	}()
	return &cliproxyexecutor.StreamResult{
		Headers: http.Header{"Content-Type": []string{"text/event-stream"}},
		Chunks:  out,
	}, nil
}

type windsurfCascadeRun struct {
	ID                string
	Created           int64
	Model             string
	RequestedModel    string
	TranslatedRequest []byte
	CascadeID         string
	LS                *WindsurfLanguageServer
	GRPC              *windsurfGRPCClient
	ToolAllowlist     map[string]bool
	ToolPreamble      string
}

type windsurfCascadeResult struct {
	Text         string
	Thinking     string
	ToolCalls    []windsurfToolCall
	Usage        *windsurfUsage
	FinishReason string
}

func (c *WindsurfClient) startCascade(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*windsurfCascadeRun, error) {
	settings := resolveWindsurfSettings(auth)
	apiKey, settings, err := c.resolveAPIKey(ctx, auth, settings)
	if err != nil {
		return nil, err
	}

	baseModel := windsurfNormalizeModel(thinking.ParseSuffix(req.Model).ModelName)
	spec, ok := windsurfModelSpecFor(baseModel)
	if !ok {
		return nil, statusErr{code: http.StatusBadRequest, msg: fmt.Sprintf("windsurf model %q is not in the native catalog", baseModel)}
	}

	from := opts.SourceFormat
	to := sdktranslator.FromString("openai")
	translated := sdktranslator.TranslateRequest(from, to, baseModel, req.Payload, false)
	translated, err = thinking.ApplyThinking(translated, req.Model, from.String(), to.String(), windsurfProvider)
	if err != nil {
		return nil, err
	}
	translated, _ = sjson.SetBytes(translated, "model", baseModel)
	translated, _ = sjson.DeleteBytes(translated, "stream")

	prompt := windsurfCascadePromptFromOpenAI(translated)
	toolPreamble, allowlist := windsurfBuildToolPreamble(translated)

	ls, err := c.lsPool.Ensure(ctx, auth)
	if err != nil {
		return nil, err
	}
	if errWarm := c.warmupCascade(ctx, ls, settings, apiKey); errWarm != nil {
		return nil, errWarm
	}
	grpc := newWindsurfGRPCClient(ls.Port, ls.CSRFToken)
	startResp, err := grpc.Unary(ctx, windsurfRPCStartCascade, windsurfBuildStartCascadeRequest(apiKey, ls.SessionID), 30*time.Second)
	if err != nil {
		closeWindsurfGRPCClient(ls.Port)
		return nil, err
	}
	cascadeID, err := windsurfParseStartCascadeResponse(startResp)
	if err != nil {
		return nil, err
	}
	if cascadeID == "" {
		return nil, statusErr{code: http.StatusBadGateway, msg: "windsurf StartCascade returned an empty cascade_id"}
	}
	sendReq, err := windsurfBuildSendCascadeMessageRequest(apiKey, cascadeID, prompt, spec, ls.SessionID, toolPreamble)
	if err != nil {
		return nil, err
	}
	if _, err = grpc.Unary(ctx, windsurfRPCSendUserCascadeMessage, sendReq, 45*time.Second); err != nil {
		closeWindsurfGRPCClient(ls.Port)
		return nil, err
	}
	return &windsurfCascadeRun{
		ID:                "chatcmpl-" + strings.ReplaceAll(uuid.NewString(), "-", ""),
		Created:           time.Now().Unix(),
		Model:             baseModel,
		RequestedModel:    req.Model,
		TranslatedRequest: translated,
		CascadeID:         cascadeID,
		LS:                ls,
		GRPC:              grpc,
		ToolAllowlist:     allowlist,
		ToolPreamble:      toolPreamble,
	}, nil
}

func (c *WindsurfClient) resolveAPIKey(ctx context.Context, auth *cliproxyauth.Auth, settings windsurfSettings) (string, windsurfSettings, error) {
	if apiKey := strings.TrimSpace(settings.APIKey); apiKey != "" {
		return apiKey, settings, nil
	}
	if auth != nil && auth.Metadata != nil {
		if apiKey, _ := auth.Metadata["api_key"].(string); strings.TrimSpace(apiKey) != "" {
			settings.APIKey = strings.TrimSpace(apiKey)
			return settings.APIKey, settings, nil
		}
	}
	token := strings.TrimSpace(settings.AuthToken)
	if token == "" {
		return "", settings, statusErr{code: http.StatusUnauthorized, msg: "windsurf native transport requires api_key or auth_token in auths/*.json"}
	}
	reg, err := c.registerWithAuthToken(ctx, auth, token)
	if err != nil {
		return "", settings, err
	}
	settings.APIKey = reg.APIKey
	if reg.APIServerURL != "" {
		settings.APIServerURL = reg.APIServerURL
	}
	if auth != nil {
		if auth.Attributes == nil {
			auth.Attributes = map[string]string{}
		}
		auth.Attributes["api_key"] = settings.APIKey
		if reg.APIServerURL != "" {
			auth.Attributes["api_server_url"] = reg.APIServerURL
		}
		if auth.Metadata == nil {
			auth.Metadata = map[string]any{}
		}
		auth.Metadata["api_key"] = settings.APIKey
		if reg.Name != "" {
			auth.Metadata["name"] = reg.Name
		}
		if reg.APIServerURL != "" {
			auth.Metadata["api_server_url"] = reg.APIServerURL
		}
	}
	return settings.APIKey, settings, nil
}

type windsurfRegisterResult struct {
	APIKey       string
	Name         string
	APIServerURL string
}

func (c *WindsurfClient) registerWithAuthToken(ctx context.Context, auth *cliproxyauth.Auth, token string) (windsurfRegisterResult, error) {
	body, _ := json.Marshal(map[string]string{"firebase_id_token": token})
	client := helps.NewProxyAwareHTTPClient(ctx, c.cfg, auth, 30*time.Second)
	endpoints := []string{
		"https://register.windsurf.com/exa.seat_management_pb.SeatManagementService/RegisterUser",
		"https://api.codeium.com/register_user/",
	}
	var errs []string
	for _, endpoint := range endpoints {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return windsurfRegisterResult{}, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Connect-Protocol-Version", "1")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "windsurf/1.9600.41")
		resp, err := client.Do(req)
		if err != nil {
			errs = append(errs, endpoint+": "+err.Error())
			continue
		}
		data, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode >= 400 {
			errs = append(errs, fmt.Sprintf("%s: HTTP %d %s", endpoint, resp.StatusCode, string(data)))
			continue
		}
		var raw map[string]any
		if err := json.Unmarshal(data, &raw); err != nil {
			errs = append(errs, endpoint+": "+err.Error())
			continue
		}
		apiKey := firstJSONStrings(raw, "api_key", "apiKey")
		if apiKey == "" {
			errs = append(errs, endpoint+": response did not include api_key")
			continue
		}
		return windsurfRegisterResult{
			APIKey:       apiKey,
			Name:         firstJSONStrings(raw, "name"),
			APIServerURL: firstJSONStrings(raw, "api_server_url", "apiServerUrl"),
		}, nil
	}
	return windsurfRegisterResult{}, statusErr{code: http.StatusUnauthorized, msg: "windsurf auth_token registration failed: " + strings.Join(errs, " | ")}
}

func firstJSONStrings(raw map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := raw[key].(string); ok {
			if trimmed := strings.TrimSpace(value); trimmed != "" {
				return trimmed
			}
		}
	}
	return ""
}

func (c *WindsurfClient) warmupCascade(ctx context.Context, ls *WindsurfLanguageServer, settings windsurfSettings, apiKey string) error {
	key := windsurfWorkspacePath(settings.WorkspaceDir, apiKey)
	if ls.WarmedFor == key {
		return nil
	}
	if err := ensureWindsurfWorkspace(key); err != nil {
		return err
	}
	grpc := newWindsurfGRPCClient(ls.Port, ls.CSRFToken)
	sessionID := ls.SessionID
	if sessionID == "" {
		sessionID = uuid.NewString()
		ls.SessionID = sessionID
	}
	calls := []struct {
		path    string
		payload []byte
	}{
		{windsurfRPCInitializePanelState, windsurfBuildInitializePanelStateRequest(apiKey, sessionID, true)},
		{windsurfRPCAddTrackedWorkspace, windsurfBuildAddTrackedWorkspaceRequest(key)},
		{windsurfRPCUpdateWorkspaceTrust, windsurfBuildUpdateWorkspaceTrustRequest(apiKey, sessionID, true)},
		{windsurfRPCHeartbeat, windsurfBuildHeartbeatRequest(apiKey, sessionID)},
	}
	for _, call := range calls {
		if _, err := grpc.Unary(ctx, call.path, call.payload, 30*time.Second); err != nil {
			closeWindsurfGRPCClient(ls.Port)
			ls.WarmedFor = ""
			return err
		}
	}
	ls.WorkspacePath = key
	ls.WarmedFor = key
	return nil
}

func ensureWindsurfWorkspace(path string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("windsurf workspace path is empty")
	}
	if err := os.MkdirAll(filepath.Join(path, "src"), 0700); err != nil {
		return err
	}
	files := map[string]string{
		"package.json": `{"name":"proxy-workspace-stub","version":"0.0.0","private":true,"description":"Placeholder created by CLIProxyAPIPlus for Windsurf native Cascade."}` + "\n",
		"README.md":    "# Proxy workspace placeholder\n\nThis directory is only used to initialize the Windsurf language server workspace.\n",
		".gitignore":   "# proxy workspace placeholder\n",
	}
	for name, content := range files {
		full := filepath.Join(path, name)
		if _, err := os.Stat(full); err == nil {
			continue
		}
		if err := os.WriteFile(full, []byte(content), 0600); err != nil {
			return err
		}
	}
	return nil
}

func (c *WindsurfClient) pollCascade(ctx context.Context, run *windsurfCascadeRun, onDelta func(string) bool) (*windsurfCascadeResult, error) {
	deadline := time.Now().Add(10 * time.Minute)
	lastText := ""
	lastProgress := time.Now()
	var final windsurfCascadeResult
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		stepsResp, err := run.GRPC.Unary(ctx, windsurfRPCGetTrajectorySteps, windsurfBuildGetTrajectoryStepsRequest(run.CascadeID, 0), 30*time.Second)
		if err != nil {
			closeWindsurfGRPCClient(run.LS.Port)
			return nil, err
		}
		steps, err := windsurfParseTrajectorySteps(stepsResp)
		if err != nil {
			return nil, err
		}
		text, thinking, toolCalls, usage, stepErr := windsurfAggregateSteps(steps, run.ToolAllowlist)
		if text != lastText {
			if onDelta != nil && strings.HasPrefix(text, lastText) {
				if !onDelta(text[len(lastText):]) {
					return nil, ctx.Err()
				}
			}
			lastText = text
			lastProgress = time.Now()
		}
		final.Text = text
		final.Thinking = thinking
		final.ToolCalls = toolCalls
		final.Usage = usage
		if stepErr != "" && text == "" && len(toolCalls) == 0 {
			return nil, statusErr{code: http.StatusBadGateway, msg: stepErr}
		}

		statusResp, err := run.GRPC.Unary(ctx, windsurfRPCGetTrajectory, windsurfBuildGetTrajectoryRequest(run.CascadeID), 15*time.Second)
		if err != nil {
			closeWindsurfGRPCClient(run.LS.Port)
			return nil, err
		}
		status, err := windsurfParseTrajectoryStatus(statusResp)
		if err != nil {
			return nil, err
		}
		if status == 1 && (text != "" || len(toolCalls) > 0) {
			final.FinishReason = "stop"
			if len(toolCalls) > 0 {
				final.FinishReason = "tool_calls"
				final.Text = strings.TrimSpace(windsurfRemoveToolCallText(final.Text))
			}
			return &final, nil
		}
		if time.Now().After(deadline) {
			return nil, statusErr{code: http.StatusGatewayTimeout, msg: "windsurf cascade timed out"}
		}
		if time.Since(lastProgress) > 45*time.Second && text == "" && len(toolCalls) == 0 {
			return nil, statusErr{code: http.StatusGatewayTimeout, msg: "windsurf cascade stalled before producing output"}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

func windsurfAggregateSteps(steps []windsurfTrajectoryStep, allowlist map[string]bool) (string, string, []windsurfToolCall, *windsurfUsage, string) {
	var bestText string
	var thinking strings.Builder
	var stepErr string
	usage := &windsurfUsage{}
	seenUsage := false
	var calls []windsurfToolCall
	for _, step := range steps {
		if step.Text != "" {
			bestText = step.Text
		}
		if step.Thinking != "" {
			if thinking.Len() > 0 {
				thinking.WriteByte('\n')
			}
			thinking.WriteString(step.Thinking)
		}
		if step.ErrorText != "" {
			stepErr = step.ErrorText
		}
		if step.Usage != nil {
			usage.InputTokens += step.Usage.InputTokens
			usage.OutputTokens += step.Usage.OutputTokens
			usage.CacheReadTokens += step.Usage.CacheReadTokens
			usage.CacheWriteTokens += step.Usage.CacheWriteTokens
			seenUsage = true
		}
		for _, call := range step.ToolCalls {
			if allowlist == nil || allowlist[call.Name] {
				calls = append(calls, call)
			}
		}
	}
	if parsed := windsurfParseEmulatedToolCalls(bestText, allowlist); len(parsed) > 0 {
		calls = append(calls, parsed...)
	}
	if !seenUsage {
		usage = nil
	}
	return bestText, thinking.String(), calls, usage, stepErr
}

func windsurfCascadePromptFromOpenAI(payload []byte) string {
	messages := gjson.GetBytes(payload, "messages").Array()
	var systemParts []string
	var history []string
	for _, msg := range messages {
		role := msg.Get("role").String()
		content := windsurfOpenAIContentToString(msg.Get("content"))
		if role == "system" || role == "developer" {
			if content != "" {
				systemParts = append(systemParts, windsurfCompactSystem(content))
			}
			continue
		}
		if role == "tool" {
			id := msg.Get("tool_call_id").String()
			if id != "" {
				history = append(history, fmt.Sprintf("<tool_result id=%q>%s</tool_result>", id, content))
			} else {
				history = append(history, "<tool_result>"+content+"</tool_result>")
			}
			continue
		}
		if role == "assistant" && len(msg.Get("tool_calls").Array()) > 0 {
			history = append(history, "<assistant_tool_calls>"+msg.Get("tool_calls").Raw+"</assistant_tool_calls>")
			if content != "" {
				history = append(history, "<assistant>"+content+"</assistant>")
			}
			continue
		}
		if content == "" {
			continue
		}
		tag := role
		if tag == "" {
			tag = "user"
		}
		history = append(history, fmt.Sprintf("<%s>%s</%s>", tag, content, tag))
	}
	var b strings.Builder
	if len(systemParts) > 0 {
		b.WriteString("<system>\n")
		b.WriteString(strings.Join(systemParts, "\n\n"))
		b.WriteString("\n</system>\n\n")
	}
	if len(history) > 0 {
		b.WriteString("<conversation>\n")
		b.WriteString(strings.Join(history, "\n"))
		b.WriteString("\n</conversation>")
	}
	return b.String()
}

func windsurfOpenAIContentToString(value gjson.Result) string {
	if !value.Exists() || value.Type == gjson.Null {
		return ""
	}
	if value.Type == gjson.String {
		return value.String()
	}
	if value.IsArray() {
		parts := value.Array()
		out := make([]string, 0, len(parts))
		for _, part := range parts {
			t := strings.ToLower(part.Get("type").String())
			switch t {
			case "text", "input_text":
				out = append(out, part.Get("text").String())
			case "image_url", "input_image", "image":
				out = append(out, "[Image omitted from text history]")
			default:
				if text := part.Get("text").String(); text != "" {
					out = append(out, text)
				} else {
					out = append(out, part.Raw)
				}
			}
		}
		return strings.Join(out, "")
	}
	return value.Raw
}

func windsurfCompactSystem(text string) string {
	text = regexp.MustCompile(`(?im)^x-anthropic-billing-header:[^\n]*(\n|$)`).ReplaceAllString(text, "")
	text = regexp.MustCompile(`(?i)(^|[\n.!?]\s*)You are `).ReplaceAllString(text, "${1}The assistant is ")
	if len(text) <= 4000 {
		return strings.TrimSpace(text)
	}
	return strings.TrimSpace(text[:4000]) + "\n[system prompt compacted]"
}

func windsurfBuildToolPreamble(payload []byte) (string, map[string]bool) {
	tools := gjson.GetBytes(payload, "tools").Array()
	if len(tools) == 0 {
		return "", nil
	}
	allow := make(map[string]bool, len(tools))
	var b strings.Builder
	b.WriteString("Client-side tools are available. Do not execute tools yourself. When a tool is needed, output exactly:\n")
	b.WriteString(`<tool_call>{"name":"tool_name","arguments":{}}</tool_call>` + "\n\n")
	b.WriteString("Available tools:\n")
	for _, tool := range tools {
		fn := tool.Get("function")
		name := fn.Get("name").String()
		if name == "" {
			continue
		}
		allow[name] = true
		b.WriteString("- ")
		b.WriteString(name)
		if desc := fn.Get("description").String(); desc != "" {
			b.WriteString(": ")
			b.WriteString(desc)
		}
		if params := fn.Get("parameters").Raw; params != "" {
			b.WriteString("\n  parameters: ")
			b.WriteString(params)
		}
		b.WriteByte('\n')
	}
	if len(allow) == 0 {
		return "", nil
	}
	return b.String(), allow
}

var windsurfToolCallRE = regexp.MustCompile(`(?s)<tool_call>\s*(\{.*?\})\s*</tool_call>`)

func windsurfParseEmulatedToolCalls(text string, allowlist map[string]bool) []windsurfToolCall {
	matches := windsurfToolCallRE.FindAllStringSubmatch(text, -1)
	out := make([]windsurfToolCall, 0, len(matches))
	for i, match := range matches {
		var raw struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal([]byte(match[1]), &raw); err != nil || raw.Name == "" {
			continue
		}
		if allowlist != nil && !allowlist[raw.Name] {
			continue
		}
		args := string(raw.Arguments)
		if args == "" || args == "null" {
			args = "{}"
		}
		out = append(out, windsurfToolCall{
			ID:            fmt.Sprintf("call_%s_%d", strings.ReplaceAll(uuid.NewString(), "-", "")[:12], i),
			Name:          raw.Name,
			ArgumentsJSON: args,
		})
	}
	return out
}

func windsurfRemoveToolCallText(text string) string {
	return strings.TrimSpace(windsurfToolCallRE.ReplaceAllString(text, ""))
}

func buildWindsurfOpenAIResponse(run *windsurfCascadeRun, result *windsurfCascadeResult) []byte {
	message := map[string]any{
		"role":    "assistant",
		"content": result.Text,
	}
	if len(result.ToolCalls) > 0 {
		message["content"] = nil
		message["tool_calls"] = windsurfOpenAIToolCalls(result.ToolCalls)
	}
	finish := result.FinishReason
	if finish == "" {
		finish = "stop"
	}
	body := map[string]any{
		"id":      run.ID,
		"object":  "chat.completion",
		"created": run.Created,
		"model":   run.Model,
		"choices": []map[string]any{{
			"index":         0,
			"message":       message,
			"finish_reason": finish,
		}},
		"usage": windsurfOpenAIUsageMap(result.Usage),
	}
	out, _ := json.Marshal(body)
	return out
}

func windsurfOpenAIToolCalls(calls []windsurfToolCall) []map[string]any {
	out := make([]map[string]any, 0, len(calls))
	for i, call := range calls {
		id := call.ID
		if id == "" {
			id = fmt.Sprintf("call_%d_%s", i, strings.ReplaceAll(uuid.NewString(), "-", "")[:10])
		}
		args := call.ArgumentsJSON
		if strings.TrimSpace(args) == "" {
			args = "{}"
		}
		out = append(out, map[string]any{
			"id":   id,
			"type": "function",
			"function": map[string]any{
				"name":      call.Name,
				"arguments": args,
			},
		})
	}
	return out
}

func windsurfOpenAIUsageMap(usage *windsurfUsage) map[string]any {
	if usage == nil {
		return map[string]any{"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
	}
	total := usage.InputTokens + usage.OutputTokens
	out := map[string]any{
		"prompt_tokens":     usage.InputTokens,
		"completion_tokens": usage.OutputTokens,
		"total_tokens":      total,
	}
	if usage.CacheReadTokens > 0 {
		out["prompt_tokens_details"] = map[string]any{"cached_tokens": usage.CacheReadTokens}
	}
	return out
}

func windsurfUsageDetail(u *windsurfUsage) usage.Detail {
	if u == nil {
		return usage.Detail{}
	}
	return usage.Detail{
		InputTokens:         int64(u.InputTokens),
		OutputTokens:        int64(u.OutputTokens),
		TotalTokens:         int64(u.InputTokens + u.OutputTokens),
		CacheReadTokens:     int64(u.CacheReadTokens),
		CacheCreationTokens: int64(u.CacheWriteTokens),
		CachedTokens:        int64(u.CacheReadTokens),
	}
}

func windsurfOpenAIStreamRoleChunk(run *windsurfCascadeRun, role string) []byte {
	return windsurfOpenAIStreamChunk(run, map[string]any{"role": role}, nil)
}

func windsurfOpenAIStreamContentChunk(run *windsurfCascadeRun, content string) []byte {
	return windsurfOpenAIStreamChunk(run, map[string]any{"content": content}, nil)
}

func windsurfOpenAIStreamToolCallChunk(run *windsurfCascadeRun, calls []windsurfToolCall) []byte {
	return windsurfOpenAIStreamChunk(run, map[string]any{"tool_calls": windsurfOpenAIStreamToolCalls(calls)}, nil)
}

func windsurfOpenAIStreamFinishChunk(run *windsurfCascadeRun, finish string) []byte {
	if finish == "" {
		finish = "stop"
	}
	return windsurfOpenAIStreamChunk(run, map[string]any{}, &finish)
}

func windsurfOpenAIStreamChunk(run *windsurfCascadeRun, delta map[string]any, finish *string) []byte {
	choice := map[string]any{
		"index": 0,
		"delta": delta,
	}
	if finish == nil {
		choice["finish_reason"] = nil
	} else {
		choice["finish_reason"] = *finish
	}
	body := map[string]any{
		"id":      run.ID,
		"object":  "chat.completion.chunk",
		"created": run.Created,
		"model":   run.Model,
		"choices": []map[string]any{choice},
	}
	raw, _ := json.Marshal(body)
	return append([]byte("data: "), raw...)
}

func windsurfOpenAIStreamToolCalls(calls []windsurfToolCall) []map[string]any {
	out := make([]map[string]any, 0, len(calls))
	for i, call := range calls {
		args := call.ArgumentsJSON
		if strings.TrimSpace(args) == "" {
			args = "{}"
		}
		id := call.ID
		if id == "" {
			id = fmt.Sprintf("call_%d_%s", i, strings.ReplaceAll(uuid.NewString(), "-", "")[:10])
		}
		out = append(out, map[string]any{
			"index": i,
			"id":    id,
			"type":  "function",
			"function": map[string]any{
				"name":      call.Name,
				"arguments": args,
			},
		})
	}
	return out
}

func windsurfBodySummary(payload []byte) []byte {
	if len(payload) <= windsurfDefaultMaxBodyBytes {
		return payload
	}
	return bytes.Clone(payload[:windsurfDefaultMaxBodyBytes])
}
