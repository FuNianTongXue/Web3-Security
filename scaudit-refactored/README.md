# 研发安全管理平台（Go 桌面版）

这是一个本地运行的研发安全客户端，采用企业级模块化入口：

- 审计工作台：负责规则管理、项目选择、执行扫描
- 系统设置：负责 GitLab 对接参数统一配置

## 一、启动方式

```bash
go run ./cmd/scaudit-desktop
```

启动后访问：

- 模块总览：[http://127.0.0.1:8088/](http://127.0.0.1:8088/)
- 静态代码审计模块：[http://127.0.0.1:8088/static-audit](http://127.0.0.1:8088/static-audit)
- 系统设置模块：[http://127.0.0.1:8088/settings](http://127.0.0.1:8088/settings)

## 二、核心流程

1. 在“系统设置”页面保存 GitLab 与 Jira（直连）参数，并验证连接。
2. 回到“审计工作台”，加载项目/分支。
3. 勾选规则并执行扫描。

## 三、动态审计编排（含 n8n）

动态审计入口位于“审计工作台 -> 一点五、动态代码审计编排（AI Skills）”。

- 审计深度：`quick / standard / deep`
- 编排方式：
  - `auto`：优先走 n8n（已配置时），否则回退本地工具链
  - `n8n`：强制走 n8n webhook
  - `local`：强制本地执行（Slither/Forge/Echidna）

在“系统设置 -> Jira 接入（直连）”中配置：

- `jira_enabled`
- `jira_base_url`
- `jira_user`
- `jira_api_token`
- `jira_auth_mode`（`basic` / `bearer`）
- `jira_project_key`
- `jira_timeout_seconds`

说明：

- Jira 当前为直连模式，不依赖 n8n。
- n8n 编排能力保留在动态审计模块，后续可按需启用。

在“系统设置 -> 动态审计编排（n8n）”中配置（可选）：

- `n8n_enabled`
- `n8n_base_url`（可选）
- `n8n_webhook_url`（推荐直接配置）
- `n8n_api_token`（可选）
- `n8n_timeout_seconds`
- `n8n_auth_mode`（`bearer` / `x-n8n-api-key` / `custom-header` / `none`）
- `n8n_auth_header`（Header 鉴权名称）
- `n8n_retry_count`
- `n8n_retry_backoff_ms`

说明：

- `auto` 模式下，如果 n8n 调用失败，会自动回退本地执行并在运行摘要中记录 `orchestrator_fallback`。
- 动态审计结果会参与门禁评估并触发治理告警。
- 系统设置页支持 `测试 n8n 连接`，优先探测 `GET /api/v1/workflows?limit=1` 连通性。

## 四、规则管理能力

规则文件：`data/rules.json`

- 新增规则（自定义检测器）
- 修改规则（ID 相同即更新）
- 启用/停用规则
- 删除规则（仅自定义规则，内置规则不可删除）
- 勾选规则后执行扫描

## 五、报告输出

扫描后自动生成：

- `reports/audit_report_*.json`
- `reports/audit_report_*.md`

仓库缓存目录：

- `.cache/repos/<namespace_project>`

## 六、静态审计项目扫描新增能力

- 支持项目上传到项目库（本地目录 / 本地文件 / 压缩包）
- 支持删除已上传项目
- 支持从项目库直接发起扫描
- 支持本地目录、单文件、压缩包直接扫描（无需先上传）
- 扫描后自动生成 AST 图模型：
  - 图数据库存储（属性图 JSON）：`data/lake/graphs/<scan_id>/ast_graph.json`
  - 结构图文件（DOT）：`data/lake/graphs/<scan_id>/ast_graph.dot`

## 七、大项目并发能力

- 静态扫描引擎改为并行文件扫描（基于 worker pool，多线程并发）
- 并发线程数、任务队列长度已纳入系统设置（`data/settings.json`）
- 扫描元数据与报告写入数据湖目录：
  - `data/lake/projects/`（项目存储）
  - `data/lake/scans/`（扫描元数据）
  - `data/lake/graphs/`（AST 图存储）

## 八、企业级综合架构（可配置）

默认内置组件：

- Hadoop（离线原始数据）
- Hive（离线数仓）
- MySQL（事务元数据）
- NebulaGraph（图数据库）
- Flink（流式计算）
- Kafka（消息总线）
- Elasticsearch（检索分析）
- Redis（缓存加速）

配置存储：

- `data/enterprise_architecture.json`

后端接口：

- `GET /api/settings/enterprise`：读取企业架构配置
- `POST /api/settings/enterprise`：保存企业架构配置
- `POST /api/settings/enterprise/test`：组件连通性检测（支持全量/单组件）

## 九、漏洞报告主字段（中文）

报告 JSON / Markdown 已支持以下主字段：

- 项目id
- 项目名称
- 项目简称
- 所属部门
- 所属团队
- 项目负责人
- 安全责任人
- git分支id
- 漏洞描述
- 修复方案
- 缓解措施
- 备注
