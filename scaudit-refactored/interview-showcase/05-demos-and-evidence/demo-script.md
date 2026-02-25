# 05 Demo Script

## 15 分钟演示脚本

1. 启动平台
   - `make run`
   - 打开 `/static-audit` 与 `/settings`
2. 导入漏洞样例
   - 使用 `samples/vuln-suite` 或 `samples/vuln-suite.zip`
3. 选择规则并执行扫描
   - 展示扫描结果摘要（P0/P1/P2）
4. 展示报告导出
   - 查看 Markdown/JSON 报告内容
5. 展示治理动作
   - 演示抑制条目审批或发布门禁评估接口
6. 收尾
   - 强调“从发现到治理再到发布”的工程闭环

## Demo 话术（精简版）

- “我实现的不是单一扫描器，而是一个可落地的安全治理平台。”
- “每个流程都有数据沉淀到 `data/lake`，可追溯、可审计。”
- “关键能力都配了测试，尤其是权限、门禁和治理路径。”

## 证据路径

- `samples/vuln-suite/README.md`
- `reports/`
- `data/lake/`
- `internal/webapp/server.go`
