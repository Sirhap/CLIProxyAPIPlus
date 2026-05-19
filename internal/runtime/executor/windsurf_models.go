package executor

import "strings"

type windsurfModelSpec struct {
	ID        string
	Provider  string
	EnumValue int
	ModelUID  string
}

var windsurfModelCatalog = map[string]windsurfModelSpec{
	"claude-4.5-sonnet":          {ID: "claude-4.5-sonnet", Provider: "anthropic", EnumValue: 353, ModelUID: "MODEL_PRIVATE_2"},
	"claude-4.5-sonnet-thinking": {ID: "claude-4.5-sonnet-thinking", Provider: "anthropic", EnumValue: 354, ModelUID: "MODEL_PRIVATE_3"},
	"claude-sonnet-4.6":          {ID: "claude-sonnet-4.6", Provider: "anthropic", ModelUID: "claude-sonnet-4-6"},
	"claude-sonnet-4.6-thinking": {ID: "claude-sonnet-4.6-thinking", Provider: "anthropic", ModelUID: "claude-sonnet-4-6-thinking"},
	"claude-opus-4-7-medium":     {ID: "claude-opus-4-7-medium", Provider: "anthropic", ModelUID: "claude-opus-4-7-medium"},
	"claude-opus-4-7-high":       {ID: "claude-opus-4-7-high", Provider: "anthropic", ModelUID: "claude-opus-4-7-high"},
	"claude-opus-4-7-xhigh":      {ID: "claude-opus-4-7-xhigh", Provider: "anthropic", ModelUID: "claude-opus-4-7-xhigh"},
	"gpt-5.2":                    {ID: "gpt-5.2", Provider: "openai", EnumValue: 401, ModelUID: "MODEL_GPT_5_2_MEDIUM"},
	"gpt-5.2-low":                {ID: "gpt-5.2-low", Provider: "openai", EnumValue: 400, ModelUID: "MODEL_GPT_5_2_LOW"},
	"gpt-5.2-high":               {ID: "gpt-5.2-high", Provider: "openai", EnumValue: 402, ModelUID: "MODEL_GPT_5_2_HIGH"},
	"gpt-5.2-xhigh":              {ID: "gpt-5.2-xhigh", Provider: "openai", EnumValue: 403, ModelUID: "MODEL_GPT_5_2_XHIGH"},
	"gpt-5.4-medium":             {ID: "gpt-5.4-medium", Provider: "openai", ModelUID: "gpt-5-4-medium"},
	"gpt-5.5":                    {ID: "gpt-5.5", Provider: "openai", ModelUID: "gpt-5-5-medium"},
	"gemini-3.0-pro":             {ID: "gemini-3.0-pro", Provider: "google", EnumValue: 412, ModelUID: "MODEL_GOOGLE_GEMINI_3_0_PRO_LOW"},
	"gemini-3.0-flash":           {ID: "gemini-3.0-flash", Provider: "google", EnumValue: 415, ModelUID: "MODEL_GOOGLE_GEMINI_3_0_FLASH_MEDIUM"},
	"glm-4.7":                    {ID: "glm-4.7", Provider: "zhipu", EnumValue: 417, ModelUID: "MODEL_GLM_4_7"},
	"glm-5.1":                    {ID: "glm-5.1", Provider: "zhipu", ModelUID: "glm-5-1"},
	"kimi-k2.5":                  {ID: "kimi-k2.5", Provider: "moonshot", ModelUID: "kimi-k2-5"},
	"swe-1.6":                    {ID: "swe-1.6", Provider: "windsurf", EnumValue: 420, ModelUID: "MODEL_SWE_1_6"},
	"swe-1.6-fast":               {ID: "swe-1.6-fast", Provider: "windsurf", EnumValue: 421, ModelUID: "MODEL_SWE_1_6_FAST"},
}

var windsurfModelAliases = map[string]string{
	"claude-sonnet-4-6":          "claude-sonnet-4.6",
	"claude-sonnet-4-6-thinking": "claude-sonnet-4.6-thinking",
	"claude-4.6":                 "claude-sonnet-4.6",
	"claude-4.6-thinking":        "claude-sonnet-4.6-thinking",
	"sonnet-4.6":                 "claude-sonnet-4.6",
	"sonnet-4.6-thinking":        "claude-sonnet-4.6-thinking",
	"claude-sonnet-4.5":          "claude-4.5-sonnet",
	"claude-sonnet-4.5-thinking": "claude-4.5-sonnet-thinking",
	"gpt-5.2-medium":             "gpt-5.2",
	"gpt-5-2-medium":             "gpt-5.2",
	"gpt-5.4":                    "gpt-5.4-medium",
	"gpt-5-4-medium":             "gpt-5.4-medium",
	"gpt-5-5":                    "gpt-5.5",
	"gpt-5-5-medium":             "gpt-5.5",
	"swe-1-6":                    "swe-1.6",
	"swe-1-6-fast":               "swe-1.6-fast",
	"kimi-k2-5":                  "kimi-k2.5",
}

func windsurfResolveModel(name string) string {
	key := strings.TrimSpace(strings.TrimPrefix(name, "windsurf/"))
	if key == "" {
		return ""
	}
	if _, ok := windsurfModelCatalog[key]; ok {
		return key
	}
	lower := strings.ToLower(key)
	if resolved, ok := windsurfModelAliases[lower]; ok {
		return resolved
	}
	if _, ok := windsurfModelCatalog[lower]; ok {
		return lower
	}
	return key
}

func windsurfModelSpecFor(name string) (windsurfModelSpec, bool) {
	resolved := windsurfResolveModel(name)
	spec, ok := windsurfModelCatalog[resolved]
	return spec, ok
}
