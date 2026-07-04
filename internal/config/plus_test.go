package config

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestPlusConfigFieldsFlattenToTopLevelYAML(t *testing.T) {
	cfg := Config{
		PlusConfig: PlusConfig{
			KiroPreferredEndpoint: "cli",
		},
	}

	out, err := yaml.Marshal(&cfg)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var roundTripped map[string]interface{}
	if err := yaml.Unmarshal(out, &roundTripped); err != nil {
		t.Fatalf("unmarshal to map failed: %v", err)
	}

	if _, ok := roundTripped["kiro-preferred-endpoint"]; !ok {
		t.Fatalf("expected top-level key 'kiro-preferred-endpoint' in marshaled YAML, got keys: %v", keysOf(roundTripped))
	}
}

func keysOf(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
