package platform

type ToolModule struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Type         string `json:"type"`
	Status       string `json:"status"`
	Description  string `json:"description"`
	Configurable bool   `json:"configurable"`
	ReservedNote string `json:"reserved_note"`
}

func DefaultToolModules() []ToolModule {
	return []ToolModule{
		{
			ID:           "builtin-static-rules",
			Name:         "内置静态规则引擎（Slither风格）",
			Type:         "静态分析",
			Status:       "可用",
			Description:  "当前默认引擎，支持规则管理、规则启停、按勾选规则执行。",
			Configurable: true,
			ReservedNote: "当前版本主引擎。",
		},
		{
			ID:           "plugin-slither-cli",
			Name:         "Slither CLI 适配器",
			Type:         "静态分析",
			Status:       "可用",
			Description:  "已接入原生 Slither 命令行输出解析，支持检测器精准下发与运行时诊断。",
			Configurable: true,
			ReservedNote: "支持 scan_engine=slither/auto，失败可回退内置引擎。",
		},
		{
			ID:           "plugin-mythril",
			Name:         "Mythril 适配器",
			Type:         "符号执行",
			Status:       "预留",
			Description:  "预留接入符号执行扫描能力。",
			Configurable: true,
			ReservedNote: "建议后续与规则引擎做结果合并。",
		},
		{
			ID:           "plugin-echidna",
			Name:         "Echidna 适配器",
			Type:         "模糊测试",
			Status:       "可用（编排执行）",
			Description:  "动态审计编排已支持 Echidna CLI 任务执行与阻塞治理统计。",
			Configurable: true,
			ReservedNote: "建议后续接入属性模板库与最小复现实例自动生成。",
		},
		{
			ID:           "plugin-foundry",
			Name:         "Foundry 测试适配器",
			Type:         "单元测试/集成测试",
			Status:       "可用（编排执行）",
			Description:  "动态审计编排已支持 forge test 与 invariant 回归任务。",
			Configurable: true,
			ReservedNote: "建议后续补充覆盖率、gas 与回归基线聚合。",
		},
	}
}
