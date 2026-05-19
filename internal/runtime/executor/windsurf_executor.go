package executor

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	log "github.com/sirupsen/logrus"
)

// WindsurfExecutor is the Windsurf provider entrypoint.
//
// The file layout intentionally mirrors dwgx/WindsurfAPI:
//
//	windsurf_executor.go   -> src/handlers/chat.js + src/server.js provider entry
//	windsurf_client.go     -> src/client.js
//	windsurf_langserver.go -> src/langserver.js
//	windsurf_grpc.go       -> src/grpc.js
//	windsurf_proto.go      -> src/windsurf.js
//
// Native LS/gRPC is the default path. transport=sidecar is kept as an
// explicit compatibility path for operators who still run the Node WindsurfAPI
// server beside CLIProxyAPIPlus.
type WindsurfExecutor struct {
	cfg    *config.Config
	compat *OpenAICompatExecutor
	native *WindsurfClient
}

func NewWindsurfExecutor(cfg *config.Config) *WindsurfExecutor {
	return &WindsurfExecutor{
		cfg:    cfg,
		compat: NewOpenAICompatExecutor(windsurfProvider, cfg),
		native: NewWindsurfClient(cfg),
	}
}

func (e *WindsurfExecutor) Identifier() string { return windsurfProvider }

func (e *WindsurfExecutor) Execute(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	if windsurfUseNative(auth) {
		return e.native.ChatCompletions(ctx, auth, req, opts)
	}
	return e.compat.Execute(ctx, auth, req, opts)
}

func (e *WindsurfExecutor) ExecuteStream(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	if windsurfUseNative(auth) {
		return e.native.ChatCompletionsStream(ctx, auth, req, opts)
	}
	return e.compat.ExecuteStream(ctx, auth, req, opts)
}

func (e *WindsurfExecutor) Refresh(ctx context.Context, auth *cliproxyauth.Auth) (*cliproxyauth.Auth, error) {
	if windsurfUseNative(auth) {
		log.Debug("windsurf executor: native refresh is currently a no-op")
		return auth, nil
	}
	return e.compat.Refresh(ctx, auth)
}

func (e *WindsurfExecutor) CountTokens(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return e.compat.CountTokens(ctx, auth, req, opts)
}

func (e *WindsurfExecutor) HttpRequest(ctx context.Context, auth *cliproxyauth.Auth, req *http.Request) (*http.Response, error) {
	if windsurfUseNative(auth) {
		return nil, fmt.Errorf("windsurf native transport does not expose raw HTTP request forwarding")
	}
	return e.compat.HttpRequest(ctx, auth, req)
}

func windsurfUseNative(auth *cliproxyauth.Auth) bool {
	transport := ""
	if auth != nil && auth.Attributes != nil {
		transport = strings.ToLower(strings.TrimSpace(auth.Attributes["transport"]))
	}
	return transport == "" || transport == "native" || transport == "ls" || transport == "language-server"
}
