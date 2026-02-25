package audit

type Rule struct {
	ID            string   `json:"id"`
	Title         string   `json:"title"`
	Severity      string   `json:"severity"`
	Category      string   `json:"category"`
	Impact        string   `json:"impact"`
	Confidence    string   `json:"confidence"`
	SlitherRef    string   `json:"slither_ref"`
	Description   string   `json:"description"`
	Remediation   string   `json:"remediation"`
	Regex         string   `json:"regex"`
	Enabled       bool     `json:"enabled"`
	Builtin       bool     `json:"builtin"`
	ApplyProjects []string `json:"apply_projects,omitempty"`
}

func DefaultRules() []Rule {
	rules := []Rule{
		{
			ID:          "slither-reentrancy-eth",
			Title:       "可能存在 ETH 重入",
			Severity:    "P0",
			Category:    "Reentrancy",
			Impact:      "High",
			Confidence:  "Medium",
			SlitherRef:  "reentrancy-eth",
			Description: "检测 call/value/send 等外部转账调用缺少重入防护。",
			Remediation: "使用 CEI 顺序、ReentrancyGuard，并在外部调用前更新状态。",
			Regex:       `\.call\s*\{|\.call\s*\(|\.send\s*\(|\.transfer\s*\(`,
		},
		{
			ID:          "slither-reentrancy-no-eth",
			Title:       "可能存在无 ETH 重入",
			Severity:    "P0",
			Category:    "Reentrancy",
			Impact:      "High",
			Confidence:  "Medium",
			SlitherRef:  "reentrancy-no-eth",
			Description: "检测外部合约交互（swap/mint/burn/callback）缺少互斥保护。",
			Remediation: "对关键状态路径增加 nonReentrant 并拆分外部调用逻辑。",
			Regex:       `swap\s*\(|mint\s*\(|burn\s*\(|callback|onERC|external\s+call`,
		},
		{
			ID:          "slither-tx-origin",
			Title:       "使用 tx.origin 做认证",
			Severity:    "P0",
			Category:    "Access Control",
			Impact:      "High",
			Confidence:  "High",
			SlitherRef:  "tx-origin",
			Description: "tx.origin 认证容易被钓鱼合约绕过。",
			Remediation: "认证仅使用 msg.sender + 角色控制。",
			Regex:       `tx\.origin`,
		},
		{
			ID:          "slither-controlled-delegatecall",
			Title:       "可控 delegatecall",
			Severity:    "P0",
			Category:    "Code Execution",
			Impact:      "High",
			Confidence:  "Medium",
			SlitherRef:  "controlled-delegatecall",
			Description: "delegatecall 目标若可控将导致存储污染或接管。",
			Remediation: "目标地址使用固定实现/白名单，并限制升级入口。",
			Regex:       `delegatecall\s*\(`,
		},
		{
			ID:          "slither-suicidal",
			Title:       "危险销毁函数",
			Severity:    "P0",
			Category:    "Access Control",
			Impact:      "High",
			Confidence:  "Medium",
			SlitherRef:  "suicidal",
			Description: "检测 selfdestruct/suicide，若权限不足会导致合约不可用。",
			Remediation: "严格限制销毁权限，优先停用而非销毁。",
			Regex:       `selfdestruct\s*\(|suicide\s*\(`,
		},
		{
			ID:          "slither-unprotected-upgrade",
			Title:       "升级入口可能未保护",
			Severity:    "P0",
			Category:    "Upgradeability",
			Impact:      "High",
			Confidence:  "Medium",
			SlitherRef:  "unprotected-upgrade",
			Description: "升级函数缺少 onlyOwner/role 校验会被恶意升级。",
			Remediation: "升级函数强制访问控制与 timelock，多签治理。",
			Regex:       `upgradeTo\s*\(|upgradeToAndCall\s*\(|setImplementation\s*\(`,
		},
		{
			ID:          "slither-arbitrary-send-erc20",
			Title:       "ERC20 转账接收方可控",
			Severity:    "P1",
			Category:    "Access Control",
			Impact:      "Medium",
			Confidence:  "Medium",
			SlitherRef:  "arbitrary-send-erc20",
			Description: "transfer/transferFrom 接收方若直接取自外部参数存在劫持风险。",
			Remediation: "关键转账目标使用白名单或固定受益人。",
			Regex:       `transferFrom\s*\(|transfer\s*\(`,
		},
		{
			ID:          "slither-unchecked-transfer",
			Title:       "ERC20 返回值未检查",
			Severity:    "P1",
			Category:    "Standards",
			Impact:      "Medium",
			Confidence:  "Medium",
			SlitherRef:  "unchecked-transfer",
			Description: "部分 ERC20 不 revert 仅返回 false，未检查会导致静默失败。",
			Remediation: "使用 SafeERC20 或显式检查返回值。",
			Regex:       `\.transfer\s*\(|\.transferFrom\s*\(`,
		},
		{
			ID:          "slither-weak-prng",
			Title:       "弱随机源",
			Severity:    "P1",
			Category:    "Cryptography",
			Impact:      "Medium",
			Confidence:  "High",
			SlitherRef:  "weak-prng",
			Description: "基于 block.timestamp/blockhash 等链上变量生成随机数可被操纵。",
			Remediation: "使用 VRF/commit-reveal/可信随机服务。",
			Regex:       `block\.timestamp|blockhash\s*\(|block\.number|keccak256\s*\(`,
		},
		{
			ID:          "slither-timestamp",
			Title:       "时间戳依赖",
			Severity:    "P1",
			Category:    "Logic",
			Impact:      "Medium",
			Confidence:  "High",
			SlitherRef:  "timestamp",
			Description: "关键逻辑直接依赖 block.timestamp 可能受矿工轻度操纵。",
			Remediation: "使用宽容时间窗口并避免将 timestamp 作为唯一安全条件。",
			Regex:       `block\.timestamp`,
		},
		{
			ID:          "slither-divide-before-multiply",
			Title:       "先除后乘精度损失",
			Severity:    "P1",
			Category:    "Math",
			Impact:      "Medium",
			Confidence:  "Medium",
			SlitherRef:  "divide-before-multiply",
			Description: "先除后乘在整数算术下会引发精度损失。",
			Remediation: "在溢出安全前提下优先先乘后除并统一舍入策略。",
			Regex:       `/\s*\w+\s*\*|\w+\s*/\s*\w+\s*\*`,
		},
		{
			ID:          "slither-calls-loop",
			Title:       "循环中外部调用",
			Severity:    "P1",
			Category:    "DoS",
			Impact:      "Medium",
			Confidence:  "Medium",
			SlitherRef:  "calls-loop",
			Description: "for/while 中执行外部调用可能导致 gas DoS。",
			Remediation: "批处理拆分、pull 模式、限制循环规模。",
			Regex:       `for\s*\(|while\s*\(|\.call\s*\(|transfer\s*\(`,
		},
		{
			ID:          "slither-assembly",
			Title:       "内联 assembly 高风险区",
			Severity:    "P2",
			Category:    "Maintainability",
			Impact:      "Low",
			Confidence:  "High",
			SlitherRef:  "assembly",
			Description: "assembly 容易绕过编译器安全检查。",
			Remediation: "缩小 assembly 范围并添加单元测试/审计注释。",
			Regex:       `assembly\s*\{`,
		},
		{
			ID:          "slither-shadowing-state",
			Title:       "变量遮蔽风险",
			Severity:    "P2",
			Category:    "Code Quality",
			Impact:      "Low",
			Confidence:  "Low",
			SlitherRef:  "shadowing-state",
			Description: "局部变量/参数与状态变量同名会降低可读性并引入错误。",
			Remediation: "统一命名规范，避免与状态变量重名。",
			Regex:       `\b(uint|int|address|bytes|string|bool)\s+\w+\s*=`,
		},
		{
			ID:          "slither-missing-zero-check",
			Title:       "关键地址缺少零地址校验",
			Severity:    "P1",
			Category:    "Validation",
			Impact:      "Medium",
			Confidence:  "Medium",
			SlitherRef:  "missing-zero-check",
			Description: "设置管理员/实现/资金接收地址时缺少 address(0) 校验。",
			Remediation: "关键地址赋值/更新时强制 require(addr != address(0))。",
			Regex:       `address\s+\w+|set\w*\s*\(\s*address`,
		},
		{
			ID:          "slither-oracle-manipulation",
			Title:       "可操纵现货价作为预言机",
			Severity:    "P0",
			Category:    "Oracle",
			Impact:      "High",
			Confidence:  "Medium",
			SlitherRef:  "price-manipulation (custom)",
			Description: "检测直接以 AMM spot/getReserves 用于估值或借贷。",
			Remediation: "改用独立预言机 + TWAP + 偏离熔断。",
			Regex:       `getReserves\s*\(|spot\s*price|consult\s*\(`,
		},
	}
	for i := range rules {
		rules[i].Enabled = true
		rules[i].Builtin = true
	}
	return rules
}
