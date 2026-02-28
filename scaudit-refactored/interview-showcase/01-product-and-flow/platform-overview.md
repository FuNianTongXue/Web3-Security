# 01 Product and Flow

## 平台定位

- 研发安全管理平台（本地可运行，Web UI）
- 面向 Web3/合约审计与研发治理流程
- 核心目标：把“发现漏洞”升级为“可治理、可验收、可发布门禁”的完整链路

## 关键流程

1. 系统设置：配置 GitLab/Jira/扫描引擎参数
2. 项目接入：项目上传（本地目录/文件/压缩包/GitLab）
3. 规则执行：按规则集执行静态扫描
4. 动态审计：按 `quick/standard/deep` 与 `local/auto` 编排执行
5. 报告输出：生成 JSON + Markdown 报告
6. 治理闭环：误报抑制、漏洞工单、发布门禁评估、审批与生产确认

## 证据路径

- `README.md`
- `QUICKSTART.md`
- `internal/webapp/server.go`
- `internal/webapp/dynamic_audit.go`
