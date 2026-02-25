# Interview Showcase (SCaudit Refactored)

> 说明：当前整理基于本地仓库 `scaudit-refactored`，用于面试时展示技术能力。

## 目录导航

- `01-product-and-flow/`：产品定位、业务流程、场景价值
- `02-architecture-and-code/`：架构拆分、模块职责、API 能力地图
- `03-security-capabilities/`：认证鉴权、审计能力、治理与门禁
- `04-engineering-and-delivery/`：测试、交付、部署与工程化能力
- `05-demos-and-evidence/`：演示脚本、样例漏洞、审计报告证据
- `06-reference-docs/`：原始文档归档（便于快速取证）

## 面试讲解顺序（10~15 分钟）

1. 先讲产品闭环：代码审计 -> 漏洞治理 -> 发布门禁 -> 生产确认。
2. 再讲系统架构：`cmd` 入口 + `internal` 模块化 + `data/lake` 数据分层。
3. 讲安全能力：JWT/bcrypt、限流、规则引擎、动态审计编排、抑制治理、发布审批。
4. 讲工程能力：`116` 个测试用例、`92` 个 API 路由、Docker/K8s/CI 配置。
5. 最后现场演示：用 `samples/vuln-suite` 触发扫描，展示 `reports/` 报告输出。

## 快速亮点（可直接复述）

- 不是单点扫描工具，而是“扫描 + 治理 + 门禁 + 审批”的平台化实现。
- 代码与能力是可证据化的，每个能力在仓库里都有对应实现文件和测试。
- 支持静态审计、动态审计编排（local/n8n/auto fallback）和 GitLab 流程接入。
