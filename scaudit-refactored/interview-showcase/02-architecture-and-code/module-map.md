# 02 Architecture and Code Map

## 总体结构

- `cmd/`：多入口模式（desktop / web / cli / api）
- `internal/audit/`：规则与扫描引擎（静态审计核心）
- `internal/webapp/`：主服务与 UI/API，当前核心实现区
- `internal/auth/`：JWT 与密码哈希
- `internal/gitlab/`：GitLab API 接入
- `internal/graph/`：AST 图模型生成
- `internal/api/middleware/`：鉴权与限流中间件
- `data/lake/`：项目、扫描、图、漏洞、门禁等数据落盘

## 可量化代码证据

- Go 源码文件：`74`
- 测试文件：`36`
- 测试用例（`func Test*`）：`116`
- HTTP 路由注册（`mux.HandleFunc`）：`92`

## 路由能力分组（节选）

- 项目管理：`/api/projects/*`
- 规则管理：`/api/rules*`
- 扫描执行与图谱：`/api/scan*`
- 动态审计：`/api/dynamic-audit/*`
- 报告管理：`/api/reports/*`
- 漏洞治理：`/api/findings/*`
- 发布门禁：`/api/release/*`
- 配置中心：`/api/settings/*`

## 证据路径

- `internal/webapp/server.go`
- `internal/audit/scanner.go`
- `internal/audit/rules.go`
- `internal/graph/ast_graph.go`
- `data/lake/`
