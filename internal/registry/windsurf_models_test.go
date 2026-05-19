package registry

import "testing"

func TestWindsurfStaticModelsRegistered(t *testing.T) {
	models := GetStaticModelDefinitionsByChannel("windsurf")
	if len(models) == 0 {
		t.Fatal("expected windsurf static models")
	}
	if findModelInfo(models, "claude-sonnet-4.6") == nil {
		t.Fatal("expected claude-sonnet-4.6 in windsurf catalog")
	}
	if findModelInfo(models, "windsurf/claude-sonnet-4.6") == nil {
		t.Fatal("expected windsurf/claude-sonnet-4.6 alias in windsurf catalog")
	}
	if model := LookupStaticModelInfo("claude-sonnet-4.6"); model == nil || model.Type != "windsurf" {
		t.Fatalf("LookupStaticModelInfo claude-sonnet-4.6 = %#v, want windsurf model", model)
	}
	if model := LookupStaticModelInfo("windsurf/claude-sonnet-4.6"); model == nil || model.Type != "windsurf" {
		t.Fatalf("LookupStaticModelInfo windsurf/claude-sonnet-4.6 = %#v, want windsurf model", model)
	}
}
