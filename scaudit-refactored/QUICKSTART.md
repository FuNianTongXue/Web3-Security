# SCaudit Platform - 快速开始

本项目当前主要提供三种本地启动方式（桌面模式/纯 Web 模式/Docker）。

## 0. 前置要求

- Go: `1.23.x`（见 `go.mod`）

## 1. 方式1: 桌面模式（推荐）

启动后会监听 `127.0.0.1:8088` 并自动打开浏览器。

```bash
make run
# 或：
go run ./cmd/scaudit-desktop
```

指定端口/监听地址：

```bash
make run PORT=8090
make run HOST=0.0.0.0 PORT=8088
```

健康检查：

```bash
curl http://127.0.0.1:8088/health
```

常用页面：

- 首页: http://127.0.0.1:8088/
- 静态审计: http://127.0.0.1:8088/static-audit
- 系统设置: http://127.0.0.1:8088/settings
- 规则文档: http://127.0.0.1:8088/docs/rules

## 2. 方式2: 纯 Web 模式

监听 `:8088`（不自动打开浏览器）。

```bash
make run-web
# 或：
go run ./cmd/scaudit-api
```

## 3. 方式3: Docker Compose

```bash
cd deployments/docker
docker compose up -d --build
curl http://127.0.0.1:8088/health
```

## 4. 数据目录

运行时会在工作目录创建/使用：

- `data/`（配置、项目库、扫描数据湖）
- `reports/`（扫描报告）
- `.cache/`（仓库缓存）

## 5. 常见问题

- 如果遇到 Go build cache 权限错误（例如提示无法访问 `$HOME/Library/Caches/go-build`），优先使用 `make run` / `make test`（Makefile 已默认将 `GOCACHE` 指向项目内 `.gocache/`）。
- 或手动指定：`GOCACHE=$PWD/.gocache go run ./cmd/scaudit-desktop`
