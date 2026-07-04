package cliproxy

import (
	"context"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// plusExecutorConstructors maps a Plus provider key to its executor constructor.
// Registered here (rather than as inline switch cases in service.go) so that
// adding, removing, or renaming a Plus provider never touches the upstream
// switch statement in service.go, avoiding merge conflicts on upstream sync.
var plusExecutorConstructors = map[string]func(cfg *config.Config) coreauth.ProviderExecutor{
	"kimi":      func(cfg *config.Config) coreauth.ProviderExecutor { return executor.NewKimiExecutor(cfg) },
	"xai":       func(cfg *config.Config) coreauth.ProviderExecutor { return executor.NewXAIExecutor(cfg) },
	"kilo":      func(cfg *config.Config) coreauth.ProviderExecutor { return executor.NewKiloExecutor(cfg) },
	"cursor":    func(cfg *config.Config) coreauth.ProviderExecutor { return executor.NewCursorExecutor(cfg) },
	"codebuddy": func(cfg *config.Config) coreauth.ProviderExecutor { return executor.NewCodeBuddyExecutor(cfg) },
	"gitlab":    func(cfg *config.Config) coreauth.ProviderExecutor { return executor.NewGitLabExecutor(cfg) },
	"windsurf":  func(cfg *config.Config) coreauth.ProviderExecutor { return executor.NewWindsurfExecutor(cfg) },
}

// plusModelResolvers maps a Plus provider key to its model-list resolver.
// Mirrors plusExecutorConstructors: kept out of service.go's registerModelsForAuth
// switch for the same merge-conflict-avoidance reason.
var plusModelResolvers = map[string]func(a *coreauth.Auth, cfg *config.Config) []*ModelInfo{
	"kimi": func(a *coreauth.Auth, cfg *config.Config) []*ModelInfo {
		return registry.GetKimiModels()
	},
	"xai": func(a *coreauth.Auth, cfg *config.Config) []*ModelInfo {
		return registry.GetXAIModels()
	},
	"cursor": func(a *coreauth.Auth, cfg *config.Config) []*ModelInfo {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return executor.FetchCursorModels(ctx, a, cfg)
	},
	"kilo": func(a *coreauth.Auth, cfg *config.Config) []*ModelInfo {
		return executor.FetchKiloModels(context.Background(), a, cfg)
	},
	"gitlab": func(a *coreauth.Auth, cfg *config.Config) []*ModelInfo {
		return executor.GitLabModelsFromAuth(a)
	},
	"codebuddy": func(a *coreauth.Auth, cfg *config.Config) []*ModelInfo {
		return registry.GetCodeBuddyModels()
	},
	"windsurf": func(a *coreauth.Auth, cfg *config.Config) []*ModelInfo {
		return registry.GetWindsurfModels()
	},
}
