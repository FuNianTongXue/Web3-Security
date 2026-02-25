# 04 Engineering and Delivery

## 测试与质量

- 重点测试集中在 `internal/webapp`（模块级/流程级测试）
- 覆盖动态审计、门禁策略、抑制治理、权限校验、报告上传 ACL
- 具备烟雾测试与集成风格测试

## 工程化能力

- Makefile 提供构建、运行、测试、安全扫描、部署命令
- Dockerfile 为多阶段构建，运行时非 root 用户
- docker-compose 支持本地一键运行
- Kubernetes deployment/hpa/pvc 配置齐全
- GitHub Actions 包含 lint/test/security/image build 流程

## 可直接展示的命令

```bash
make run
make test
./scripts/setup_mock_gitlab_contract.sh
./scripts/test_platform_gitlab_flow.sh
```

## 证据路径

- `Makefile`
- `deployments/docker/Dockerfile`
- `deployments/docker/docker-compose.yml`
- `deployments/kubernetes/deployment.yaml`
- `.github/workflows/ci-cd.yml`
- `scripts/setup_mock_gitlab_contract.sh`
- `scripts/test_platform_gitlab_flow.sh`
