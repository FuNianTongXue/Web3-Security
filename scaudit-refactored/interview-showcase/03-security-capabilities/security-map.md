# 03 Security Capabilities

## 身份与访问控制

- `bcrypt` 密码哈希（cost=12）
- JWT 访问令牌与校验
- API 级鉴权与角色化操作入口
- 速率限制中间件（防滥用）

## 审计与检测能力

- 静态规则库（可增删改启停）
- 扫描源支持本地与 GitLab
- AST 图输出（JSON + DOT）
- 动态审计编排：`local` / `auto(映射到local)`

## 治理与发布门禁

- 抑制单（误报/风险接受）生命周期与审批
- 漏洞案例状态流转与复测确认
- 发布门禁评估 + 审批 + 生产确认
- 告警/日志/审计记录能力

## 面试可讲的“安全闭环”

1. 规则扫描发现问题
2. 漏洞进入治理案例
3. 误报与风险接受走审批
4. 发布前门禁评估阻断高风险
5. 通过后才允许生产确认

## 证据路径

- `internal/auth/password.go`
- `internal/auth/jwt.go`
- `internal/api/middleware/auth.go`
- `internal/api/middleware/rate_limiter.go`
- `internal/webapp/suppression_store.go`
- `internal/webapp/finding_case_store.go`
- `internal/webapp/release_gate_store.go`
- `internal/webapp/server_suppression_test.go`
- `internal/webapp/server_release_gate_acl_test.go`
