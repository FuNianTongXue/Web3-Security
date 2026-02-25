# SCaudit Platform - 实施路线图

## 概述
本文档提供了将原始代码迁移到优化版本的详细步骤。

## 📋 迁移检查清单

### 阶段1: 准备工作 (第1周)

- [ ] **环境准备**
  - [ ] 安装PostgreSQL 16
  - [ ] 安装Redis 7
  - [ ] 配置环境变量 (.env)
  - [ ] 生成安全密钥 (`make generate-secrets`)

- [ ] **数据迁移准备**
  - [ ] 备份现有JSON数据文件
  - [ ] 编写数据迁移脚本
  - [ ] 测试环境验证

### 阶段2: 核心重构 (第2-3周)

#### 2.1 安全加固
- [ ] **认证系统**
  ```bash
  # 文件位置
  internal/auth/jwt.go        # JWT管理
  internal/auth/password.go   # 密码哈希
  ```
  - [ ] 实现JWT认证
  - [ ] 迁移用户密码到bcrypt
  - [ ] 添加刷新令牌机制

- [ ] **输入验证**
  ```bash
  # 文件位置
  internal/validation/validator.go
  ```
  - [ ] 实现验证框架
  - [ ] 添加XSS防护
  - [ ] 添加SQL注入防护
  - [ ] 路径遍历防护

- [ ] **中间件**
  ```bash
  # 文件位置
  internal/api/middleware/auth.go
  ```
  - [ ] 认证中间件
  - [ ] CORS中间件
  - [ ] 速率限制
  - [ ] 安全头

#### 2.2 代码重构
- [ ] **拆分server.go (11,154行)**
  
  **步骤1: 提取Handler**
  ```bash
  # 创建目录
  mkdir -p internal/api/handlers
  
  # 需要创建的文件
  internal/api/handlers/auth.go      # 认证相关
  internal/api/handlers/scan.go      # 扫描相关
  internal/api/handlers/project.go   # 项目相关
  internal/api/handlers/settings.go  # 设置相关
  ```

  **步骤2: 业务逻辑层**
  ```bash
  mkdir -p internal/service
  
  # 需要创建的文件
  internal/service/scan_service.go
  internal/service/project_service.go
  internal/service/auth_service.go
  ```

  **步骤3: 数据访问层**
  ```bash
  mkdir -p internal/repository
  
  # 需要创建的文件
  internal/repository/scan_repository.go
  internal/repository/project_repository.go
  internal/repository/user_repository.go
  ```

- [ ] **模板HTML分离**
  ```bash
  # 从server.go中提取HTML模板
  # 移动到独立文件
  web/templates/home.html
  web/templates/scan.html
  web/templates/settings.html
  ```

#### 2.3 数据库迁移
- [ ] **创建迁移脚本**
  ```bash
  # 创建迁移
  make migrate-create NAME=initial_schema
  make migrate-create NAME=migrate_json_to_postgres
  ```

- [ ] **数据迁移步骤**
  1. 读取 `data/rules.json` → 插入 PostgreSQL
  2. 读取 `data/settings.json` → 插入 PostgreSQL
  3. 读取历史扫描数据 → 插入 PostgreSQL
  4. 验证数据完整性

### 阶段3: DevOps建设 (第4周)

- [ ] **Docker容器化**
  ```bash
  # 构建镜像
  make docker-build
  
  # 本地测试
  make compose-up
  make compose-logs
  ```

- [ ] **CI/CD配置**
  - [ ] 配置GitHub Actions
  - [ ] 设置自动测试
  - [ ] 配置自动部署
  - [ ] 设置代码质量检查

- [ ] **监控系统**
  - [ ] 配置Prometheus
  - [ ] 导入Grafana仪表盘
  - [ ] 配置告警规则
  - [ ] 设置日志聚合

### 阶段4: 测试与优化 (第5周)

- [ ] **单元测试**
  ```bash
  # 运行测试
  make test
  make test-coverage
  
  # 目标: 覆盖率 > 60%
  ```

- [ ] **集成测试**
  ```bash
  make test-integration
  ```

- [ ] **性能测试**
  - [ ] 负载测试
  - [ ] 压力测试
  - [ ] 数据库性能优化

- [ ] **安全扫描**
  ```bash
  make security-check
  ```

### 阶段5: 部署上线 (第6周)

- [ ] **预发布环境**
  ```bash
  # Kubernetes部署
  kubectl apply -f deployments/kubernetes/
  
  # 验证
  make k8s-status
  make k8s-logs
  ```

- [ ] **生产环境**
  - [ ] 灰度发布
  - [ ] 监控指标验证
  - [ ] 回滚计划准备

## 🔧 详细实施步骤

### Step 1: 安装依赖

```bash
# 更新go.mod
go get -u github.com/lib/pq
go get -u github.com/redis/go-redis/v9
go get -u github.com/golang-jwt/jwt/v5
go get -u golang.org/x/crypto/bcrypt
go get -u github.com/go-playground/validator/v10
go get -u github.com/microcosm-cc/bluemonday
go mod tidy
```

### Step 2: 数据迁移脚本

创建 `scripts/migrate-json-to-postgres.go`:

```go
package main

import (
    "database/sql"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "log"
    
    _ "github.com/lib/pq"
)

func main() {
    // 连接数据库
    db, err := sql.Open("postgres", 
        "host=localhost port=5432 user=scaudit password=xxx dbname=scaudit sslmode=disable")
    if err != nil {
        log.Fatal(err)
    }
    defer db.Close()
    
    // 迁移rules.json
    if err := migrateRules(db); err != nil {
        log.Fatal("Failed to migrate rules:", err)
    }
    
    // 迁移settings.json
    if err := migrateSettings(db); err != nil {
        log.Fatal("Failed to migrate settings:", err)
    }
    
    fmt.Println("Migration completed successfully!")
}

func migrateRules(db *sql.DB) error {
    // 读取JSON文件
    data, err := ioutil.ReadFile("data/rules.json")
    if err != nil {
        return err
    }
    
    var rules []Rule
    if err := json.Unmarshal(data, &rules); err != nil {
        return err
    }
    
    // 插入数据库
    for _, rule := range rules {
        _, err := db.Exec(`
            INSERT INTO rules (id, name, description, severity, enabled)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (id) DO UPDATE SET
                name = $2, description = $3, severity = $4, enabled = $5
        `, rule.ID, rule.Name, rule.Description, rule.Severity, rule.Enabled)
        
        if err != nil {
            return err
        }
    }
    
    return nil
}

func migrateSettings(db *sql.DB) error {
    // 类似实现
    return nil
}
```

### Step 3: 逐步替换server.go

#### 创建新的路由器

```go
// internal/api/router.go
package api

import (
    "net/http"
    "scaudit/internal/api/handlers"
    "scaudit/internal/api/middleware"
)

type RouterConfig struct {
    Database   *db.DB
    Cache      *cache.RedisCache
    JWTManager *auth.JWTManager
    Config     *config.Config
}

func NewRouter(cfg RouterConfig) http.Handler {
    mux := http.NewServeMux()
    
    // 初始化handlers
    authHandler := handlers.NewAuthHandler(cfg.Database, cfg.JWTManager)
    scanHandler := handlers.NewScanHandler(cfg.Database, cfg.Cache)
    
    // 公开路由
    mux.HandleFunc("/api/v1/auth/login", authHandler.Login)
    mux.HandleFunc("/api/v1/auth/register", authHandler.Register)
    
    // 受保护路由
    protected := http.NewServeMux()
    protected.HandleFunc("/api/v1/scans", scanHandler.List)
    protected.HandleFunc("/api/v1/scans/create", scanHandler.Create)
    
    // 应用中间件
    handler := middleware.SecurityHeadersMiddleware(mux)
    handler = middleware.CORSMiddleware(cfg.Config.CORS.AllowedOrigins)(handler)
    handler = middleware.LoggingMiddleware(handler)
    
    return handler
}
```

### Step 4: 验证迁移

```bash
# 运行测试
go test ./...

# 启动应用
go run cmd/scaudit-api/main.go

# 测试API
curl http://localhost:8088/health
curl -X POST http://localhost:8088/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"password"}'
```

## 📊 进度跟踪

| 阶段 | 任务 | 状态 | 负责人 | 预计完成 |
|------|------|------|--------|----------|
| 1 | 环境准备 | ⏳ | DevOps | Week 1 |
| 2 | 安全加固 | ⏳ | Backend | Week 2 |
| 2 | 代码重构 | ⏳ | Backend | Week 2-3 |
| 2 | 数据迁移 | ⏳ | Backend | Week 3 |
| 3 | Docker化 | ⏳ | DevOps | Week 4 |
| 3 | CI/CD | ⏳ | DevOps | Week 4 |
| 3 | 监控 | ⏳ | DevOps | Week 4 |
| 4 | 测试 | ⏳ | QA | Week 5 |
| 5 | 部署 | ⏳ | DevOps | Week 6 |

## 🚨 风险与缓解

| 风险 | 影响 | 概率 | 缓解措施 |
|------|------|------|----------|
| 数据迁移失败 | 高 | 中 | 完整备份、回滚方案、分步验证 |
| 性能下降 | 中 | 低 | 性能测试、连接池优化、缓存策略 |
| 兼容性问题 | 中 | 中 | 版本兼容测试、API版本管理 |
| 安全漏洞 | 高 | 低 | 安全审计、渗透测试、依赖扫描 |

## 📞 支持联系

- 技术支持: tech@scaudit.example.com
- 项目经理: pm@scaudit.example.com
- 紧急联系: oncall@scaudit.example.com

---

**最后更新**: 2025-02-08
**版本**: 1.0
