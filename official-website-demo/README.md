# BlockSecure-Web (Vue3 + Go) — 黑金科技风官网 + 管理后台（Docker 一键启动）

## 一键启动
在项目根目录执行：
```bash
docker compose up -d --build
```

访问：
- 官网首页：http://localhost
- 管理后台：http://localhost/admin

## 管理后台登录
后台口令来自 `ADMIN_TOKEN`（docker-compose.yaml 里配置）：
- 默认：`change-me-please`
- 进入 /admin 后输入 token 即可管理内容（产品、联系方式、站点配置等）

> 生产环境务必修改 `ADMIN_TOKEN`。

## 上传微信二维码
后台“Contact”里点 **Upload QR** 上传图片，上传后会生成 `wechatQrUrl=/uploads/xxx.png`，前台可直接展示。

## 常用命令
查看日志：
```bash
docker compose logs -f backend
docker compose logs -f frontend
```

停止：
```bash
docker compose down
```


## 构建提示（Go 依赖）
后端 Dockerfile 会在容器内执行 `go mod tidy` 来自动生成/更新 go.sum，避免本地缺少 go.sum 导致的构建失败。


## 构建提示（前端依赖）
前端 Dockerfile 使用 `npm install`（而非 `npm ci`），避免因为缺少 package-lock.json 导致构建失败。


## 已修复：SQLite 依赖无需 CGO
后端改用 `github.com/glebarez/sqlite`（基于 pure-Go 的 modernc SQLite），不再依赖 `mattn/go-sqlite3` 的 CGO。


## 容器权限与启动顺序
- 后端默认以 root 运行，避免 named volume 挂载后 `/data` `/uploads` 目录权限导致启动失败。
- 前端 Nginx 使用 Docker DNS resolver 延迟解析后端，后端尚未启动时也不会因 upstream 解析失败而退出。


## 后台管理
- 地址：http://localhost/admin
- 默认 Token：见 `docker-compose.yaml` 的 `ADMIN_TOKEN`（默认 `admin123456`，建议部署后立即修改）。

## 如果页面仍显示旧英文
如果你之前跑过并持久化了数据库，旧的站点配置会被优先读取。执行：
```bash
docker compose down -v
docker compose up -d --build
```

