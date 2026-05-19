package registry

// GetWindsurfModels returns the initial static Windsurf model catalog.
//
// The source catalog is dwgx/WindsurfAPI src/models.js. Keep this list small
// and conservative for the first native-provider migration; once the
// GetCascadeModelConfigs path is ported, dynamic discovery can expand it at
// runtime the same way WindsurfAPI does.
func GetWindsurfModels() []*ModelInfo {
	base := []*ModelInfo{
		windsurfModel("claude-4.5-sonnet", "anthropic", "Claude 4.5 Sonnet", 200000, 64000, []string{"tools"}),
		windsurfModel("claude-4.5-sonnet-thinking", "anthropic", "Claude 4.5 Sonnet Thinking", 200000, 64000, []string{"tools"}),
		windsurfModel("claude-sonnet-4.6", "anthropic", "Claude 4.6 Sonnet", 200000, 64000, []string{"tools"}),
		windsurfModel("claude-sonnet-4.6-thinking", "anthropic", "Claude 4.6 Sonnet Thinking", 200000, 64000, []string{"tools"}),
		windsurfModel("claude-opus-4-7-medium", "anthropic", "Claude Opus 4.7 Medium", 1000000, 128000, []string{"tools"}),
		windsurfModel("claude-opus-4-7-high", "anthropic", "Claude Opus 4.7 High", 1000000, 128000, []string{"tools"}),
		windsurfModel("claude-opus-4-7-xhigh", "anthropic", "Claude Opus 4.7 XHigh", 1000000, 128000, []string{"tools"}),
		windsurfModel("gpt-5.2", "openai", "GPT 5.2", 272000, 128000, []string{"tools"}),
		windsurfModel("gpt-5.4-medium", "openai", "GPT 5.4 Medium", 272000, 128000, []string{"tools"}),
		windsurfModel("gpt-5.5", "openai", "GPT 5.5", 272000, 128000, []string{"tools"}),
		windsurfModel("gemini-3.0-pro", "google", "Gemini 3.0 Pro", 1000000, 65536, []string{"tools"}),
		windsurfModel("gemini-3.0-flash", "google", "Gemini 3.0 Flash", 1000000, 65536, []string{"tools"}),
		windsurfModel("glm-4.7", "zhipu", "GLM 4.7", 128000, 64000, []string{"tools"}),
		windsurfModel("glm-5.1", "zhipu", "GLM 5.1", 128000, 64000, []string{"tools"}),
		windsurfModel("kimi-k2.5", "moonshot", "Kimi K2.5", 128000, 64000, []string{"tools"}),
		windsurfModel("swe-1.6", "windsurf", "Windsurf SWE 1.6", 200000, 64000, []string{"tools"}),
		windsurfModel("swe-1.6-fast", "windsurf", "Windsurf SWE 1.6 Fast", 200000, 64000, []string{"tools"}),
	}
	models := make([]*ModelInfo, 0, len(base)*2)
	for _, model := range base {
		models = append(models, model)
		alias := *model
		alias.ID = "windsurf/" + model.ID
		alias.Version = alias.ID
		alias.DisplayName = "Windsurf " + model.DisplayName
		models = append(models, &alias)
	}
	return cloneModelInfos(models)
}

func windsurfModel(id, owner, display string, contextLength, maxOutput int, params []string) *ModelInfo {
	return &ModelInfo{
		ID:                  id,
		Object:              "model",
		Created:             1775001600, // 2026-04-01, placeholder until dynamic catalog is ported.
		OwnedBy:             owner,
		Type:                "windsurf",
		DisplayName:         display,
		Version:             id,
		ContextLength:       contextLength,
		MaxCompletionTokens: maxOutput,
		SupportedParameters: params,
		SupportedEndpoints:  []string{"/chat/completions", "/responses", "/messages"},
	}
}
