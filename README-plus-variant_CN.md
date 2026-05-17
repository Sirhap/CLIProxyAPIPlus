# Plus 变种说明

本文档记录本 fork 相对基线新增的后端能力，方便后续跟进上游更新时快速判断哪些改动需要保留。

## 新增管理端认证能力

- Codex device flow
- CodeBuddy browser OAuth
- Kiro Portal 登录
- Kiro AWS Builder ID auth code flow
- Kiro IAM Identity Center（auth code / device）
- Kiro IDE token 导入

## Kiro 认证分工

- **Kiro Portal**：推荐的新社交登录入口，生成 `app.kiro.dev/signin` 链接，当前承接 Google / GitHub 社交登录结果。
- **Kiro AWS Builder ID**：保留 device flow 与 auth code flow 两种 AWS 登录方式。
- **Kiro IDC**：面向 IAM Identity Center 账号。
- **Kiro import**：读取当前机器上的 `~/.aws/sso/cache/kiro-auth-token.json`，用于复用已经由 Kiro IDE 生成的凭据。

## 合并策略

变种实现尽量集中在独立文件中：

- `internal/api/handlers/management/auth_files_plus.go`
- `internal/api/handlers/management/auth_files_plus_test.go`
- `internal/api/management_routes_plus.go`

基线文件只保留少量接入点，后续合并上游时优先检查这些独立文件与接入点即可。
