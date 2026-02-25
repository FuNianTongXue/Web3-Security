# 研发安全管理平台 (SCaudit Platform) - 重构优化版

[![CI/CD](https://github.com/yourorg/scaudit/workflows/CI%2FCD%20Pipeline/badge.svg)](https://github.com/yourorg/scaudit/actions)
[![codecov](https://codecov.io/gh/yourorg/scaudit/branch/main/graph/badge.svg)](https://codecov.io/gh/yourorg/scaudit)
[![Go Report Card](https://goreportcard.com/badge/github.com/yourorg/scaudit)](https://goreportcard.com/report/github.com/yourorg/scaudit)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

企业级研发安全审计与管理平台，支持静态/动态代码审计、n8n工作流编排、门禁策略、治理告警等功能。

> 注意：本 README_REFACTORED.md 中关于 PostgreSQL/Redis/监控栈/CI-CD 等内容包含规划与占位描述；当前仓库可运行形态以本地文件存储 + 内置 Web UI 为主。
> 实际启动方式请以 `QUICKSTART.md` 为准。

## 🎯 重构优化亮点

### 架构改进
- ✅ **安全加固**: JWT认证、bcrypt密码哈希、输入验证、审计日志
- ✅ **代码质量**: 拆分巨石代码(11,154行→模块化)、分层架构、测试覆盖>60%
- ✅ **DevOps**: Docker容器化、K8s编排、CI/CD自动化、完整监控体系
- ✅ **数据库**: PostgreSQL替代JSON文件、连接池优化、索引设计
- ✅ **缓存**: Redis缓存层、分布式会话管理
- ✅ **监控**: Prometheus指标、Grafana仪表盘、ELK日志聚合

### 安全增强
```
原版问题                     → 优化方案
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SHA256密码哈希(无盐)        → bcrypt(cost=12)
无会话管理                   → JWT + 刷新令牌
缺乏输入验证                 → 完整验证框架
密码明文存储                 → 加密存储+密钥管理
无审计日志                   → 结构化审计日志
```

## 🚀 快速开始

以 `QUICKSTART.md` 为准，这里给最短可复现的启动命令。

### 桌面模式（推荐）

```bash
make run
# 或：
go run ./cmd/scaudit-desktop
```

启动后访问 `http://127.0.0.1:8088/`，健康检查 `GET /health`。

### 纯 Web 模式

```bash
make run-web
# 或：
go run ./cmd/scaudit-api
```

### Docker Compose（仅启动应用本体）

```bash
cd deployments/docker
docker compose up -d --build
curl http://127.0.0.1:8088/health
```

## 📁 项目结构

```
scaudit/
├── cmd/
│   └── scaudit-api/          # 主应用入口
├── internal/
│   ├── api/                  # HTTP处理层
│   │   ├── handlers/         # 请求处理器
│   │   ├── middleware/       # 中间件(认证/日志/限流)
│   │   └── router.go         # 路由配置
│   ├── service/              # 业务逻辑层
│   ├── repository/           # 数据访问层
│   ├── domain/               # 领域模型
│   ├── auth/                 # 认证授权
│   ├── validation/           # 输入验证
│   ├── db/                   # 数据库
│   ├── cache/                # 缓存
│   ├── audit/                # 审计引擎(原有)
│   └── gitlab/               # GitLab集成(原有)
├── pkg/                      # 公共包
│   ├── logger/               # 日志
│   └── crypto/               # 加密工具
├── deployments/
│   ├── docker/               # Docker配置
│   │   ├── docker-compose.yml
│   │   └── Dockerfile
│   └── kubernetes/           # K8s配置
├── scripts/                  # 脚本工具
├── docs/                     # 文档
│   ├── api/                  # API文档
│   └── architecture/         # 架构文档
├── tests/                    # 测试
├── .github/workflows/        # CI/CD
└── config/                   # 配置文件
```

## 🔧 开发指南

### 运行测试

```bash
# 单元测试
go test ./...

# 带覆盖率
go test -cover ./...

# 生成覆盖率报告
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# 集成测试
go test -tags=integration ./...
```

### 代码检查

```bash
# 格式化代码
go fmt ./...

# 运行linter
golangci-lint run

# 安全扫描
gosec ./...
```

### 数据库迁移

```bash
# 创建新迁移
migrate create -ext sql -dir migrations -seq add_users_table

# 运行迁移
migrate -path migrations -database "postgres://user:pass@localhost:5432/scaudit?sslmode=disable" up

# 回滚
migrate -path migrations -database "postgres://user:pass@localhost:5432/scaudit?sslmode=disable" down 1
```

## 📊 监控与可观测性

### Prometheus指标
访问 http://localhost:8088/metrics 查看应用指标：
- `scaudit_http_requests_total` - HTTP请求总数
- `scaudit_http_request_duration_seconds` - 请求延迟
- `scaudit_scans_total` - 扫描任务总数
- `scaudit_findings_total` - 发现问题总数

### Grafana仪表盘
预配置仪表盘：
- **应用概览**: 请求量、错误率、延迟
- **扫描统计**: 扫描成功率、发现趋势
- **系统资源**: CPU、内存、数据库连接

### 日志查询(Kibana)
- 应用日志: `source: "scaudit-api"`
- 审计日志: `source: "scaudit-api" AND log_type: "audit"`
- 错误日志: `level: "error"`

## 🔐 安全最佳实践

### 密码策略
- 最小长度: 12字符
- 必须包含: 大写、小写、数字、特殊字符
- bcrypt哈希(cost=12)

### API认证
```bash
# 登录获取JWT
curl -X POST http://localhost:8088/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"your_password"}'

# 使用JWT访问API
curl http://localhost:8088/api/v1/scans \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### 审计日志
所有关键操作都会记录审计日志：
- 用户登录/登出
- 扫描创建/执行
- 配置修改
- 权限变更

## 🚢 生产部署

### Kubernetes部署

```bash
# 应用配置
kubectl apply -f deployments/kubernetes/configmap.yaml
kubectl apply -f deployments/kubernetes/secrets.yaml

# 部署应用
kubectl apply -f deployments/kubernetes/deployment.yaml
kubectl apply -f deployments/kubernetes/service.yaml

# 配置Ingress
kubectl apply -f deployments/kubernetes/ingress.yaml

# 查看状态
kubectl get pods -n scaudit
kubectl logs -f deployment/scaudit-api -n scaudit
```

### 扩容

```bash
# 手动扩容
kubectl scale deployment scaudit-api --replicas=5 -n scaudit

# 自动扩容(HPA)
kubectl apply -f deployments/kubernetes/hpa.yaml
```

## 📈 性能优化

### 数据库优化
- 连接池配置: MaxOpenConns=25, MaxIdleConns=5
- 索引优化: 扫描查询、发现查询
- 查询优化: 使用预编译语句

### 缓存策略
- 扫描结果缓存: 1小时
- 项目信息缓存: 5分钟
- 规则配置缓存: 15分钟

### 并发优化
- Worker池处理扫描任务
- 并发数可配置(默认5)

## 🤝 贡献指南

1. Fork项目
2. 创建特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 创建Pull Request

### 提交规范
- `feat`: 新功能
- `fix`: 修复bug
- `docs`: 文档更新
- `style`: 代码格式
- `refactor`: 代码重构
- `test`: 测试相关
- `chore`: 构建/工具相关

## 📄 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情

## 🆘 支持

- 📧 邮箱: support@scaudit.example.com
- 📖 文档: https://docs.scaudit.example.com
- 🐛 问题反馈: https://github.com/yourorg/scaudit/issues

## 🗓️ 版本历史

### v2.0.0 (2025-02-08)
- ✨ 完整架构重构
- 🔐 安全加固(JWT、bcrypt、输入验证)
- 🐳 Docker容器化
- 📊 监控系统集成
- 🧪 测试覆盖率>60%

### v1.0.0 (初始版本)
- 基础静态/动态审计功能
- GitLab集成
- n8n工作流编排

---

**Built with ❤️ by SCaudit Team**
