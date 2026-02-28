package webapp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type 超级管理员配置 struct {
	用户名  string
	密码哈希 string
	邮箱   string
}

func (c 超级管理员配置) MarshalJSON() ([]byte, error) {
	type jsonAdmin struct {
		Username     string `json:"用户名"`
		PasswordHash string `json:"密码哈希"`
		Email        string `json:"邮箱"`
	}
	return json.Marshal(jsonAdmin{
		Username:     c.用户名,
		PasswordHash: c.密码哈希,
		Email:        c.邮箱,
	})
}

func (c *超级管理员配置) UnmarshalJSON(b []byte) error {
	type jsonAdmin struct {
		Username     string `json:"用户名"`
		PasswordHash string `json:"密码哈希"`
		Email        string `json:"邮箱"`
	}
	var v jsonAdmin
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	c.用户名 = v.Username
	c.密码哈希 = v.PasswordHash
	c.邮箱 = v.Email
	return nil
}

type 平台用户 struct {
	用户ID  string
	用户名   string
	实名姓名  string
	邮箱    string
	手机号   string
	身份证号  string
	角色    string
	部门    string
	功能域   string
	数据范围  string
	登录方式  string
	钱包地址  string
	启用多因素 bool
	状态    string
	备注    string
	创建时间  string
	密码哈希  string
	KYC状态 string `json:"kyc状态"`
	证件正面  string
	证件反面  string
	活体自拍  string
}

type GitLab元数据识别规则 struct {
	启用自动识别     bool
	项目名称来源     string
	项目简称来源     string
	部门来源       string
	团队来源       string
	默认部门       string
	默认团队       string
	仓库元数据文件    string
	命名空间映射规则文本 string
}

func (r GitLab元数据识别规则) MarshalJSON() ([]byte, error) {
	type jsonRule struct {
		AutoDetect        bool   `json:"启用自动识别"`
		ProjectNameSrc    string `json:"项目名称来源"`
		ProjectShortSrc   string `json:"项目简称来源"`
		DepartmentSrc     string `json:"部门来源"`
		TeamSrc           string `json:"团队来源"`
		DefaultDepartment string `json:"默认部门"`
		DefaultTeam       string `json:"默认团队"`
		MetaFile          string `json:"仓库元数据文件"`
		MappingRulesText  string `json:"命名空间映射规则文本"`
	}
	return json.Marshal(jsonRule{
		AutoDetect:        r.启用自动识别,
		ProjectNameSrc:    r.项目名称来源,
		ProjectShortSrc:   r.项目简称来源,
		DepartmentSrc:     r.部门来源,
		TeamSrc:           r.团队来源,
		DefaultDepartment: r.默认部门,
		DefaultTeam:       r.默认团队,
		MetaFile:          r.仓库元数据文件,
		MappingRulesText:  r.命名空间映射规则文本,
	})
}

func (r *GitLab元数据识别规则) UnmarshalJSON(b []byte) error {
	type jsonRule struct {
		AutoDetect        bool   `json:"启用自动识别"`
		ProjectNameSrc    string `json:"项目名称来源"`
		ProjectShortSrc   string `json:"项目简称来源"`
		DepartmentSrc     string `json:"部门来源"`
		TeamSrc           string `json:"团队来源"`
		DefaultDepartment string `json:"默认部门"`
		DefaultTeam       string `json:"默认团队"`
		MetaFile          string `json:"仓库元数据文件"`
		MappingRulesText  string `json:"命名空间映射规则文本"`
	}
	var v jsonRule
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	r.启用自动识别 = v.AutoDetect
	r.项目名称来源 = v.ProjectNameSrc
	r.项目简称来源 = v.ProjectShortSrc
	r.部门来源 = v.DepartmentSrc
	r.团队来源 = v.TeamSrc
	r.默认部门 = v.DefaultDepartment
	r.默认团队 = v.DefaultTeam
	r.仓库元数据文件 = v.MetaFile
	r.命名空间映射规则文本 = v.MappingRulesText
	return nil
}

func (u 平台用户) MarshalJSON() ([]byte, error) {
	type jsonUser struct {
		UserID     string `json:"用户id"`
		Username   string `json:"用户名"`
		RealName   string `json:"实名姓名"`
		Email      string `json:"邮箱"`
		Phone      string `json:"手机号"`
		IDCard     string `json:"身份证号"`
		Role       string `json:"角色"`
		Department string `json:"部门"`
		Domain     string `json:"功能域"`
		DataScope  string `json:"数据范围"`
		LoginMode  string `json:"登录方式"`
		Wallet     string `json:"钱包地址"`
		MFAOn      bool   `json:"启用多因素"`
		Status     string `json:"状态"`
		Note       string `json:"备注"`
		CreatedAt  string `json:"创建时间"`
		Password   string `json:"密码哈希"`
		KYCStatus  string `json:"kyc状态"`
		IDFront    string `json:"证件正面"`
		IDBack     string `json:"证件反面"`
		Selfie     string `json:"活体自拍"`
	}
	return json.Marshal(jsonUser{
		UserID: u.用户ID, Username: u.用户名, RealName: u.实名姓名, Email: u.邮箱, Phone: u.手机号, IDCard: u.身份证号, Role: u.角色, Department: u.部门, Domain: u.功能域, DataScope: u.数据范围, LoginMode: u.登录方式, Wallet: u.钱包地址, MFAOn: u.启用多因素, Status: u.状态, Note: u.备注, CreatedAt: u.创建时间, Password: u.密码哈希, KYCStatus: u.KYC状态, IDFront: u.证件正面, IDBack: u.证件反面, Selfie: u.活体自拍,
	})
}

func (u *平台用户) UnmarshalJSON(b []byte) error {
	type jsonUser struct {
		UserID     string `json:"用户id"`
		Username   string `json:"用户名"`
		RealName   string `json:"实名姓名"`
		Email      string `json:"邮箱"`
		Phone      string `json:"手机号"`
		IDCard     string `json:"身份证号"`
		Role       string `json:"角色"`
		Department string `json:"部门"`
		Domain     string `json:"功能域"`
		DataScope  string `json:"数据范围"`
		LoginMode  string `json:"登录方式"`
		Wallet     string `json:"钱包地址"`
		MFAOn      bool   `json:"启用多因素"`
		Status     string `json:"状态"`
		Note       string `json:"备注"`
		CreatedAt  string `json:"创建时间"`
		Password   string `json:"密码哈希"`
		KYCStatus  string `json:"kyc状态"`
		IDFront    string `json:"证件正面"`
		IDBack     string `json:"证件反面"`
		Selfie     string `json:"活体自拍"`
	}
	var v jsonUser
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	u.用户ID = v.UserID
	u.用户名 = v.Username
	u.实名姓名 = v.RealName
	u.邮箱 = v.Email
	u.手机号 = v.Phone
	u.身份证号 = v.IDCard
	u.角色 = v.Role
	u.部门 = v.Department
	u.功能域 = v.Domain
	u.数据范围 = v.DataScope
	u.登录方式 = v.LoginMode
	u.钱包地址 = v.Wallet
	u.启用多因素 = v.MFAOn
	u.状态 = v.Status
	u.备注 = v.Note
	u.创建时间 = v.CreatedAt
	u.密码哈希 = v.Password
	u.KYC状态 = v.KYCStatus
	u.证件正面 = v.IDFront
	u.证件反面 = v.IDBack
	u.活体自拍 = v.Selfie
	return nil
}

type 系统管理配置 struct {
	允许注册       bool
	允许管理员登录    bool
	允许Web3签名登录 bool
	允许Web3扫码登录 bool
	允许币安风格流程   bool
	允许邮箱注册     bool
	允许手机号注册    bool
	登录必须KYC    bool
	登录必须2FA    bool
}

func (c 系统管理配置) MarshalJSON() ([]byte, error) {
	type jsonCfg struct {
		AllowRegister      bool `json:"允许注册"`
		AllowAdminLogin    bool `json:"允许管理员登录"`
		AllowWeb3SignLogin bool `json:"允许Web3签名登录"`
		AllowWeb3QRLogin   bool `json:"允许Web3扫码登录"`
		AllowBinanceFlow   bool `json:"允许币安风格流程"`
		AllowEmailRegister bool `json:"允许邮箱注册"`
		AllowPhoneRegister bool `json:"允许手机号注册"`
		LoginRequiresKYC   bool `json:"登录必须kyc"`
		LoginRequires2FA   bool `json:"登录必须2fa"`
	}
	return json.Marshal(jsonCfg{
		AllowRegister:      c.允许注册,
		AllowAdminLogin:    c.允许管理员登录,
		AllowWeb3SignLogin: c.允许Web3签名登录,
		AllowWeb3QRLogin:   c.允许Web3扫码登录,
		AllowBinanceFlow:   c.允许币安风格流程,
		AllowEmailRegister: c.允许邮箱注册,
		AllowPhoneRegister: c.允许手机号注册,
		LoginRequiresKYC:   c.登录必须KYC,
		LoginRequires2FA:   c.登录必须2FA,
	})
}

func (c *系统管理配置) UnmarshalJSON(b []byte) error {
	type jsonCfg struct {
		AllowRegister      bool `json:"允许注册"`
		AllowAdminLogin    bool `json:"允许管理员登录"`
		AllowWeb3SignLogin bool `json:"允许Web3签名登录"`
		AllowWeb3QRLogin   bool `json:"允许Web3扫码登录"`
		AllowBinanceFlow   bool `json:"允许币安风格流程"`
		AllowEmailRegister bool `json:"允许邮箱注册"`
		AllowPhoneRegister bool `json:"允许手机号注册"`
		LoginRequiresKYC   bool `json:"登录必须kyc"`
		LoginRequires2FA   bool `json:"登录必须2fa"`
	}
	var v jsonCfg
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	c.允许注册 = v.AllowRegister
	c.允许管理员登录 = v.AllowAdminLogin
	c.允许Web3签名登录 = v.AllowWeb3SignLogin
	c.允许Web3扫码登录 = v.AllowWeb3QRLogin
	c.允许币安风格流程 = v.AllowBinanceFlow
	c.允许邮箱注册 = v.AllowEmailRegister
	c.允许手机号注册 = v.AllowPhoneRegister
	c.登录必须KYC = v.LoginRequiresKYC
	c.登录必须2FA = v.LoginRequires2FA
	return nil
}

type AppSettings struct {
	GitLabURL   string `json:"gitlab_url"`
	GitLabToken string `json:"gitlab_token"`
	Jira启用      bool   `json:"jira_enabled"`
	Jira地址      string `json:"jira_base_url"`
	Jira用户名     string `json:"jira_user"`
	JiraToken   string `json:"jira_api_token"`
	Jira项目键     string `json:"jira_project_key"`
	Jira鉴权模式    string `json:"jira_auth_mode"`
	Jira超时秒     int    `json:"jira_timeout_seconds"`
	并行线程数       int
	任务队列长度      int
	日志存储路径      string
	扫描引擎        string
	Slither路径   string `json:"slither_binary"`
	Slither超时秒  int    `json:"slither_timeout_seconds"`
	架构组件列表      []企业组件
	超级管理员       超级管理员配置
	用户列表        []平台用户
	GitLab识别规则  GitLab元数据识别规则
	系统管理        系统管理配置
}

func (s AppSettings) MarshalJSON() ([]byte, error) {
	type jsonSettings struct {
		GitLabURL   string        `json:"gitlab_url"`
		GitLabToken string        `json:"gitlab_token"`
		JiraEnabled bool          `json:"jira_enabled"`
		JiraBaseURL string        `json:"jira_base_url"`
		JiraUser    string        `json:"jira_user"`
		JiraToken   string        `json:"jira_api_token"`
		JiraProject string        `json:"jira_project_key"`
		JiraAuth    string        `json:"jira_auth_mode"`
		JiraTimeout int           `json:"jira_timeout_seconds"`
		Parallelism int           `json:"并行线程数"`
		QueueSize   int           `json:"任务队列长度"`
		LogPath     string        `json:"日志存储路径"`
		ScanEngine  string        `json:"scan_engine"`
		SlitherBin  string        `json:"slither_binary"`
		SlitherTime int           `json:"slither_timeout_seconds"`
		ArchComps   []企业组件        `json:"架构组件列表"`
		Admin       超级管理员配置       `json:"超级管理员"`
		Users       []平台用户        `json:"用户列表"`
		MetaRule    GitLab元数据识别规则 `json:"gitlab_识别规则"`
		System      系统管理配置        `json:"系统管理"`
	}
	return json.Marshal(jsonSettings{
		GitLabURL: s.GitLabURL, GitLabToken: s.GitLabToken,
		JiraEnabled: s.Jira启用, JiraBaseURL: s.Jira地址, JiraUser: s.Jira用户名, JiraToken: s.JiraToken, JiraProject: s.Jira项目键, JiraAuth: s.Jira鉴权模式, JiraTimeout: s.Jira超时秒,
		Parallelism: s.并行线程数, QueueSize: s.任务队列长度, LogPath: s.日志存储路径,
		ScanEngine: s.扫描引擎, SlitherBin: s.Slither路径, SlitherTime: s.Slither超时秒,
		ArchComps: s.架构组件列表, Admin: s.超级管理员, Users: s.用户列表, MetaRule: s.GitLab识别规则, System: s.系统管理,
	})
}

func (s *AppSettings) UnmarshalJSON(b []byte) error {
	type jsonSettings struct {
		GitLabURL   string        `json:"gitlab_url"`
		GitLabToken string        `json:"gitlab_token"`
		JiraEnabled bool          `json:"jira_enabled"`
		JiraBaseURL string        `json:"jira_base_url"`
		JiraUser    string        `json:"jira_user"`
		JiraToken   string        `json:"jira_api_token"`
		JiraProject string        `json:"jira_project_key"`
		JiraAuth    string        `json:"jira_auth_mode"`
		JiraTimeout int           `json:"jira_timeout_seconds"`
		Parallelism int           `json:"并行线程数"`
		QueueSize   int           `json:"任务队列长度"`
		LogPath     string        `json:"日志存储路径"`
		ScanEngine  string        `json:"scan_engine"`
		SlitherBin  string        `json:"slither_binary"`
		SlitherTime int           `json:"slither_timeout_seconds"`
		ArchComps   []企业组件        `json:"架构组件列表"`
		Admin       超级管理员配置       `json:"超级管理员"`
		Users       []平台用户        `json:"用户列表"`
		MetaRule    GitLab元数据识别规则 `json:"gitlab_识别规则"`
		System      系统管理配置        `json:"系统管理"`
	}
	var v jsonSettings
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	s.GitLabURL = v.GitLabURL
	s.GitLabToken = v.GitLabToken
	s.Jira启用 = v.JiraEnabled
	s.Jira地址 = v.JiraBaseURL
	s.Jira用户名 = v.JiraUser
	s.JiraToken = v.JiraToken
	s.Jira项目键 = v.JiraProject
	s.Jira鉴权模式 = v.JiraAuth
	s.Jira超时秒 = v.JiraTimeout
	s.并行线程数 = v.Parallelism
	s.任务队列长度 = v.QueueSize
	s.日志存储路径 = v.LogPath
	s.扫描引擎 = v.ScanEngine
	s.Slither路径 = v.SlitherBin
	s.Slither超时秒 = v.SlitherTime
	s.架构组件列表 = v.ArchComps
	s.超级管理员 = v.Admin
	s.用户列表 = v.Users
	s.GitLab识别规则 = v.MetaRule
	s.系统管理 = v.System
	return nil
}

type SettingsStore struct {
	path string
}

func NewSettingsStore(path string) *SettingsStore {
	return &SettingsStore{path: path}
}

func (s *SettingsStore) Load() (AppSettings, error) {
	if _, err := os.Stat(s.path); err != nil {
		if os.IsNotExist(err) {
			defaultCfg := defaultSettings()
			if err := s.Save(defaultCfg); err != nil {
				return AppSettings{}, err
			}
			return defaultCfg, nil
		}
		return AppSettings{}, err
	}
	b, err := os.ReadFile(s.path)
	if err != nil {
		return AppSettings{}, err
	}
	var cfg AppSettings
	if err := json.Unmarshal(b, &cfg); err != nil {
		return AppSettings{}, err
	}
	cfg = normalizeSettings(cfg)
	return cfg, nil
}

func (s *SettingsStore) Save(cfg AppSettings) error {
	cfg = normalizeSettings(cfg)
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, b, 0o600)
}

func defaultSettings() AppSettings {
	return AppSettings{
		GitLabURL:  "https://gitlab.com",
		Jira启用:     false,
		Jira地址:     "",
		Jira用户名:    "",
		JiraToken:  "",
		Jira项目键:    "",
		Jira鉴权模式:   "basic",
		Jira超时秒:    20,
		并行线程数:      12,
		任务队列长度:     256,
		日志存储路径:     filepath.Join("data", "logs"),
		扫描引擎:       "auto",
		Slither路径:  "slither",
		Slither超时秒: 180,
		架构组件列表:     默认企业架构配置().组件列表,
		超级管理员: 超级管理员配置{
			用户名:  "admin",
			密码哈希: hashPassword("Admin@123456"),
			邮箱:   "admin@gmail.com",
		},
		用户列表: []平台用户{},
		GitLab识别规则: GitLab元数据识别规则{
			启用自动识别:     true,
			项目名称来源:     "gitlab项目名",
			项目简称来源:     "gitlab路径名",
			部门来源:       "命名空间顶级组",
			团队来源:       "命名空间次级组",
			默认部门:       "未分配部门",
			默认团队:       "未分配团队",
			仓库元数据文件:    ".sec/project_meta.yml",
			命名空间映射规则文本: "",
		},
		系统管理: 系统管理配置{
			允许注册:       true,
			允许管理员登录:    false,
			允许Web3签名登录: false,
			允许Web3扫码登录: false,
			允许币安风格流程:   true,
			允许邮箱注册:     true,
			允许手机号注册:    true,
			登录必须KYC:    true,
			登录必须2FA:    true,
		},
	}
}

func normalizeSettings(cfg AppSettings) AppSettings {
	cfg.GitLabURL = strings.TrimSpace(cfg.GitLabURL)
	cfg.GitLabToken = strings.TrimSpace(cfg.GitLabToken)
	if cfg.GitLabURL == "" {
		cfg.GitLabURL = "https://gitlab.com"
	}
	cfg.Jira地址 = strings.TrimSpace(cfg.Jira地址)
	cfg.Jira用户名 = strings.TrimSpace(cfg.Jira用户名)
	cfg.JiraToken = strings.TrimSpace(cfg.JiraToken)
	cfg.Jira项目键 = strings.TrimSpace(cfg.Jira项目键)
	cfg.Jira鉴权模式 = strings.ToLower(strings.TrimSpace(cfg.Jira鉴权模式))
	switch cfg.Jira鉴权模式 {
	case "basic", "bearer":
	default:
		cfg.Jira鉴权模式 = "basic"
	}
	if cfg.Jira超时秒 <= 0 {
		cfg.Jira超时秒 = 20
	}
	if cfg.Jira超时秒 < 3 {
		cfg.Jira超时秒 = 3
	}
	if cfg.Jira超时秒 > 120 {
		cfg.Jira超时秒 = 120
	}
	if cfg.并行线程数 <= 0 {
		cfg.并行线程数 = 12
	}
	if cfg.并行线程数 > 96 {
		cfg.并行线程数 = 96
	}
	if cfg.任务队列长度 <= 0 {
		cfg.任务队列长度 = 256
	}
	if cfg.任务队列长度 > 100000 {
		cfg.任务队列长度 = 100000
	}
	cfg.日志存储路径 = strings.TrimSpace(cfg.日志存储路径)
	if cfg.日志存储路径 == "" {
		cfg.日志存储路径 = filepath.Join("data", "logs")
	}
	cfg.扫描引擎 = strings.ToLower(strings.TrimSpace(cfg.扫描引擎))
	switch cfg.扫描引擎 {
	case "builtin", "slither", "auto":
	default:
		cfg.扫描引擎 = "auto"
	}
	cfg.Slither路径 = strings.TrimSpace(cfg.Slither路径)
	if cfg.Slither路径 == "" {
		cfg.Slither路径 = "slither"
	}
	if cfg.Slither超时秒 <= 0 {
		cfg.Slither超时秒 = 180
	}
	if cfg.Slither超时秒 < 30 {
		cfg.Slither超时秒 = 30
	}
	if cfg.Slither超时秒 > 1200 {
		cfg.Slither超时秒 = 1200
	}
	if len(cfg.架构组件列表) == 0 {
		cfg.架构组件列表 = 默认企业架构配置().组件列表
	}
	cfg.超级管理员.用户名 = strings.TrimSpace(cfg.超级管理员.用户名)
	cfg.超级管理员.密码哈希 = strings.TrimSpace(cfg.超级管理员.密码哈希)
	cfg.超级管理员.邮箱 = strings.TrimSpace(strings.ToLower(cfg.超级管理员.邮箱))
	if cfg.超级管理员.用户名 == "" {
		cfg.超级管理员.用户名 = "admin"
	}
	if cfg.超级管理员.密码哈希 == "" {
		cfg.超级管理员.密码哈希 = hashPassword("Admin@123456")
	}
	if cfg.超级管理员.邮箱 == "" {
		cfg.超级管理员.邮箱 = "admin@gmail.com"
	}
	for i := range cfg.用户列表 {
		cfg.用户列表[i].用户ID = strings.TrimSpace(cfg.用户列表[i].用户ID)
		cfg.用户列表[i].用户名 = strings.TrimSpace(cfg.用户列表[i].用户名)
		cfg.用户列表[i].实名姓名 = strings.TrimSpace(cfg.用户列表[i].实名姓名)
		cfg.用户列表[i].邮箱 = strings.TrimSpace(strings.ToLower(cfg.用户列表[i].邮箱))
		cfg.用户列表[i].手机号 = strings.TrimSpace(cfg.用户列表[i].手机号)
		cfg.用户列表[i].身份证号 = strings.TrimSpace(strings.ToUpper(cfg.用户列表[i].身份证号))
		cfg.用户列表[i].角色 = strings.TrimSpace(cfg.用户列表[i].角色)
		cfg.用户列表[i].部门 = strings.TrimSpace(cfg.用户列表[i].部门)
		cfg.用户列表[i].功能域 = strings.TrimSpace(cfg.用户列表[i].功能域)
		cfg.用户列表[i].数据范围 = strings.TrimSpace(cfg.用户列表[i].数据范围)
		cfg.用户列表[i].登录方式 = strings.TrimSpace(cfg.用户列表[i].登录方式)
		cfg.用户列表[i].钱包地址 = strings.TrimSpace(strings.ToLower(cfg.用户列表[i].钱包地址))
		cfg.用户列表[i].状态 = strings.TrimSpace(cfg.用户列表[i].状态)
		cfg.用户列表[i].备注 = strings.TrimSpace(cfg.用户列表[i].备注)
		cfg.用户列表[i].密码哈希 = strings.TrimSpace(cfg.用户列表[i].密码哈希)
		cfg.用户列表[i].KYC状态 = strings.TrimSpace(strings.ToLower(cfg.用户列表[i].KYC状态))
		if cfg.用户列表[i].角色 == "" {
			cfg.用户列表[i].角色 = "普通用户"
		}
		if cfg.用户列表[i].实名姓名 == "" {
			cfg.用户列表[i].实名姓名 = cfg.用户列表[i].用户名
		}
		if cfg.用户列表[i].登录方式 == "" {
			cfg.用户列表[i].登录方式 = "邮箱多因素登录"
		}
		if cfg.用户列表[i].登录方式 == "Web3多因素登录" && cfg.用户列表[i].钱包地址 == "" {
			cfg.用户列表[i].登录方式 = "邮箱多因素登录"
		}
		if !cfg.用户列表[i].启用多因素 {
			cfg.用户列表[i].启用多因素 = true
		}
		if cfg.用户列表[i].状态 == "" {
			cfg.用户列表[i].状态 = "启用"
		}
		if cfg.用户列表[i].部门 == "" {
			cfg.用户列表[i].部门 = "未分配部门"
		}
		if cfg.用户列表[i].功能域 == "" {
			if strings.Contains(cfg.用户列表[i].角色, "业务") {
				cfg.用户列表[i].功能域 = "工单审批,日志审计"
			} else {
				cfg.用户列表[i].功能域 = "静态+规则,工单审批"
			}
		}
		if cfg.用户列表[i].数据范围 == "" {
			cfg.用户列表[i].数据范围 = firstNonEmpty(cfg.用户列表[i].备注, "全项目")
		}
		if cfg.用户列表[i].创建时间 == "" {
			cfg.用户列表[i].创建时间 = time.Now().Format(time.RFC3339)
		}
		if cfg.用户列表[i].KYC状态 == "" {
			cfg.用户列表[i].KYC状态 = "pending"
		}
	}
	cfg.GitLab识别规则.项目名称来源 = strings.TrimSpace(cfg.GitLab识别规则.项目名称来源)
	cfg.GitLab识别规则.项目简称来源 = strings.TrimSpace(cfg.GitLab识别规则.项目简称来源)
	cfg.GitLab识别规则.部门来源 = strings.TrimSpace(cfg.GitLab识别规则.部门来源)
	cfg.GitLab识别规则.团队来源 = strings.TrimSpace(cfg.GitLab识别规则.团队来源)
	cfg.GitLab识别规则.默认部门 = strings.TrimSpace(cfg.GitLab识别规则.默认部门)
	cfg.GitLab识别规则.默认团队 = strings.TrimSpace(cfg.GitLab识别规则.默认团队)
	cfg.GitLab识别规则.仓库元数据文件 = strings.TrimSpace(cfg.GitLab识别规则.仓库元数据文件)
	cfg.GitLab识别规则.命名空间映射规则文本 = strings.TrimSpace(cfg.GitLab识别规则.命名空间映射规则文本)
	if cfg.GitLab识别规则.项目名称来源 == "" {
		cfg.GitLab识别规则.项目名称来源 = "gitlab项目名"
	}
	if cfg.GitLab识别规则.项目简称来源 == "" {
		cfg.GitLab识别规则.项目简称来源 = "gitlab路径名"
	}
	if cfg.GitLab识别规则.部门来源 == "" {
		cfg.GitLab识别规则.部门来源 = "命名空间顶级组"
	}
	if cfg.GitLab识别规则.团队来源 == "" {
		cfg.GitLab识别规则.团队来源 = "命名空间次级组"
	}
	if cfg.GitLab识别规则.默认部门 == "" {
		cfg.GitLab识别规则.默认部门 = "未分配部门"
	}
	if cfg.GitLab识别规则.默认团队 == "" {
		cfg.GitLab识别规则.默认团队 = "未分配团队"
	}
	if cfg.GitLab识别规则.仓库元数据文件 == "" {
		cfg.GitLab识别规则.仓库元数据文件 = ".sec/project_meta.yml"
	}
	// 系统管理默认保留币安流程，旧登录方式默认关闭。
	if !cfg.系统管理.允许注册 && !cfg.系统管理.允许币安风格流程 && !cfg.系统管理.允许邮箱注册 && !cfg.系统管理.允许手机号注册 {
		cfg.系统管理 = 系统管理配置{
			允许注册:       true,
			允许管理员登录:    false,
			允许Web3签名登录: false,
			允许Web3扫码登录: false,
			允许币安风格流程:   true,
			允许邮箱注册:     true,
			允许手机号注册:    true,
			登录必须KYC:    true,
			登录必须2FA:    true,
		}
	}
	if !cfg.系统管理.允许币安风格流程 && !cfg.系统管理.允许邮箱注册 && !cfg.系统管理.允许手机号注册 {
		cfg.系统管理.允许币安风格流程 = true
		cfg.系统管理.允许邮箱注册 = true
		cfg.系统管理.允许手机号注册 = true
		cfg.系统管理.登录必须KYC = true
		cfg.系统管理.登录必须2FA = true
	}
	return cfg
}

func hashPassword(password string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(password)))
	return hex.EncodeToString(sum[:])
}

func verifyPassword(hash, input string) bool {
	return strings.TrimSpace(hash) == hashPassword(input)
}

func (s *SettingsStore) AuthenticateSuperAdmin(username, password string) (超级管理员配置, error) {
	cfg, err := s.Load()
	if err != nil {
		return 超级管理员配置{}, err
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return 超级管理员配置{}, fmt.Errorf("用户名不能为空")
	}
	if username != strings.TrimSpace(cfg.超级管理员.用户名) {
		return 超级管理员配置{}, fmt.Errorf("用户名或密码错误")
	}
	if !verifyPassword(cfg.超级管理员.密码哈希, password) {
		return 超级管理员配置{}, fmt.Errorf("用户名或密码错误")
	}
	return cfg.超级管理员, nil
}

func (s *SettingsStore) UpdateSuperAdmin(currentPassword, newUsername, newPassword, newEmail string) (超级管理员配置, error) {
	cfg, err := s.Load()
	if err != nil {
		return 超级管理员配置{}, err
	}
	if !verifyPassword(cfg.超级管理员.密码哈希, currentPassword) {
		return 超级管理员配置{}, fmt.Errorf("当前密码不正确")
	}
	newUsername = strings.TrimSpace(newUsername)
	newPassword = strings.TrimSpace(newPassword)
	newEmail = strings.TrimSpace(strings.ToLower(newEmail))
	if len(newUsername) < 3 {
		return 超级管理员配置{}, fmt.Errorf("新用户名至少3位")
	}
	if len(newPassword) < 8 {
		return 超级管理员配置{}, fmt.Errorf("新密码至少8位")
	}
	cfg.超级管理员.用户名 = newUsername
	newHash := hashPassword(newPassword)
	cfg.超级管理员.密码哈希 = newHash
	if newEmail != "" {
		cfg.超级管理员.邮箱 = newEmail
	}
	if err := s.Save(cfg); err != nil {
		return 超级管理员配置{}, err
	}
	verifyCfg, err := s.Load()
	if err != nil {
		return 超级管理员配置{}, err
	}
	if strings.TrimSpace(verifyCfg.超级管理员.用户名) != newUsername || strings.TrimSpace(verifyCfg.超级管理员.密码哈希) != newHash {
		return 超级管理员配置{}, fmt.Errorf("管理员账号保存校验失败，请重试")
	}
	return cfg.超级管理员, nil
}

func (s *SettingsStore) AddUser(username, realName, email, phone, idCard, role, loginMode, wallet, note, department, domain, dataScope string, mfaOn bool) (平台用户, []平台用户, error) {
	cfg, err := s.Load()
	if err != nil {
		return 平台用户{}, nil, err
	}
	username = strings.TrimSpace(username)
	realName = strings.TrimSpace(realName)
	email = strings.TrimSpace(strings.ToLower(email))
	phone = strings.TrimSpace(phone)
	idCard = strings.TrimSpace(strings.ToUpper(idCard))
	role = strings.TrimSpace(role)
	loginMode = strings.TrimSpace(loginMode)
	wallet = strings.TrimSpace(strings.ToLower(wallet))
	note = strings.TrimSpace(note)
	department = strings.TrimSpace(department)
	domain = strings.TrimSpace(domain)
	dataScope = strings.TrimSpace(dataScope)
	if username == "" {
		return 平台用户{}, nil, fmt.Errorf("用户名不能为空")
	}
	if !strings.Contains(email, "@") {
		return 平台用户{}, nil, fmt.Errorf("邮箱格式不合法")
	}
	if realName == "" {
		realName = username
	}
	if loginMode == "Web3多因素登录" {
		if realName == "" {
			return 平台用户{}, nil, fmt.Errorf("Web3注册必须填写实名姓名")
		}
		if !isValidCNPhone(phone) {
			return 平台用户{}, nil, fmt.Errorf("Web3注册手机号格式不合法")
		}
		if !isValidIDCard(idCard) {
			return 平台用户{}, nil, fmt.Errorf("Web3注册身份证号格式不合法")
		}
	}
	for _, u := range cfg.用户列表 {
		if strings.EqualFold(u.邮箱, email) {
			return 平台用户{}, nil, fmt.Errorf("该邮箱已存在")
		}
		if wallet != "" && strings.EqualFold(strings.TrimSpace(u.钱包地址), wallet) {
			return 平台用户{}, nil, fmt.Errorf("该钱包地址已存在")
		}
		if loginMode == "Web3多因素登录" {
			if phone != "" && strings.TrimSpace(u.手机号) == phone {
				return 平台用户{}, nil, fmt.Errorf("该手机号已存在")
			}
			if idCard != "" && strings.EqualFold(strings.TrimSpace(u.身份证号), idCard) {
				return 平台用户{}, nil, fmt.Errorf("该身份证号已存在")
			}
		}
	}
	if role == "" {
		role = "普通用户"
	}
	if department == "" {
		department = "未分配部门"
	}
	if domain == "" {
		if strings.Contains(role, "业务") {
			domain = "工单审批,日志审计"
		} else {
			domain = "静态+规则,工单审批"
		}
	}
	if dataScope == "" {
		dataScope = firstNonEmpty(note, "全项目")
	}
	if loginMode == "" {
		loginMode = "邮箱多因素登录"
	}
	if loginMode == "Web3多因素登录" && wallet == "" {
		return 平台用户{}, nil, fmt.Errorf("Web3多因素登录需要钱包地址")
	}
	if !mfaOn {
		return 平台用户{}, nil, fmt.Errorf("登录安全要求：新增用户必须启用多因素")
	}
	user := 平台用户{
		用户ID:  fmt.Sprintf("usr_%d", time.Now().UnixNano()),
		用户名:   username,
		实名姓名:  realName,
		邮箱:    email,
		手机号:   phone,
		身份证号:  idCard,
		角色:    role,
		部门:    department,
		功能域:   domain,
		数据范围:  dataScope,
		登录方式:  loginMode,
		钱包地址:  wallet,
		启用多因素: mfaOn,
		状态:    "启用",
		备注:    note,
		创建时间:  time.Now().Format(time.RFC3339),
	}
	cfg.用户列表 = append(cfg.用户列表, user)
	if err := s.Save(cfg); err != nil {
		return 平台用户{}, nil, err
	}
	return user, cfg.用户列表, nil
}

func (s *SettingsStore) UpsertWeb3IdentityByEmail(name, email, phone, idCard, wallet, note string) (平台用户, []平台用户, error) {
	cfg, err := s.Load()
	if err != nil {
		return 平台用户{}, nil, err
	}
	name = strings.TrimSpace(name)
	email = strings.TrimSpace(strings.ToLower(email))
	phone = strings.TrimSpace(phone)
	idCard = strings.TrimSpace(strings.ToUpper(idCard))
	wallet = strings.TrimSpace(strings.ToLower(wallet))
	note = strings.TrimSpace(note)

	if name == "" {
		return 平台用户{}, nil, fmt.Errorf("实名姓名不能为空")
	}
	if !strings.Contains(email, "@") {
		return 平台用户{}, nil, fmt.Errorf("邮箱格式不合法")
	}
	if !isValidCNPhone(phone) {
		return 平台用户{}, nil, fmt.Errorf("手机号格式不合法")
	}
	if !isValidIDCard(idCard) {
		return 平台用户{}, nil, fmt.Errorf("身份证号格式不合法")
	}
	if wallet == "" {
		return 平台用户{}, nil, fmt.Errorf("钱包地址不能为空")
	}

	found := -1
	for i := range cfg.用户列表 {
		u := cfg.用户列表[i]
		if strings.EqualFold(strings.TrimSpace(u.邮箱), email) {
			found = i
		}
		if strings.EqualFold(strings.TrimSpace(u.钱包地址), wallet) && !strings.EqualFold(strings.TrimSpace(u.邮箱), email) {
			return 平台用户{}, nil, fmt.Errorf("该钱包地址已被其他账号绑定")
		}
		if strings.TrimSpace(u.手机号) == phone && !strings.EqualFold(strings.TrimSpace(u.邮箱), email) {
			return 平台用户{}, nil, fmt.Errorf("该手机号已存在")
		}
		if strings.EqualFold(strings.TrimSpace(u.身份证号), idCard) && !strings.EqualFold(strings.TrimSpace(u.邮箱), email) {
			return 平台用户{}, nil, fmt.Errorf("该身份证号已存在")
		}
	}

	if found >= 0 {
		u := cfg.用户列表[found]
		if strings.TrimSpace(u.钱包地址) != "" && !strings.EqualFold(strings.TrimSpace(u.钱包地址), wallet) {
			return 平台用户{}, nil, fmt.Errorf("该邮箱已绑定其他钱包地址")
		}
		u.实名姓名 = name
		if strings.TrimSpace(u.用户名) == "" {
			u.用户名 = name
		}
		u.手机号 = phone
		u.身份证号 = idCard
		u.钱包地址 = wallet
		u.登录方式 = "Web3多因素登录"
		u.启用多因素 = true
		if strings.TrimSpace(u.状态) == "" {
			u.状态 = "启用"
		}
		if strings.TrimSpace(u.部门) == "" {
			u.部门 = "未分配部门"
		}
		if strings.TrimSpace(u.功能域) == "" {
			u.功能域 = "静态+规则,工单审批"
		}
		if strings.TrimSpace(u.数据范围) == "" {
			u.数据范围 = firstNonEmpty(note, u.备注, "全项目")
		}
		if note != "" {
			u.备注 = note
		}
		cfg.用户列表[found] = u
		if err := s.Save(cfg); err != nil {
			return 平台用户{}, nil, err
		}
		return u, cfg.用户列表, nil
	}

	user := 平台用户{
		用户ID:  fmt.Sprintf("usr_%d", time.Now().UnixNano()),
		用户名:   name,
		实名姓名:  name,
		邮箱:    email,
		手机号:   phone,
		身份证号:  idCard,
		角色:    "普通用户",
		部门:    "未分配部门",
		功能域:   "静态+规则,工单审批",
		数据范围:  firstNonEmpty(note, "全项目"),
		登录方式:  "Web3多因素登录",
		钱包地址:  wallet,
		启用多因素: true,
		状态:    "启用",
		备注:    note,
		创建时间:  time.Now().Format(time.RFC3339),
	}
	cfg.用户列表 = append(cfg.用户列表, user)
	if err := s.Save(cfg); err != nil {
		return 平台用户{}, nil, err
	}
	return user, cfg.用户列表, nil
}

func isValidCNPhone(s string) bool {
	if len(s) != 11 {
		return false
	}
	if s[0] != '1' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func isValidIDCard(s string) bool {
	if len(s) != 18 {
		return false
	}
	for i := 0; i < 17; i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	last := s[17]
	return (last >= '0' && last <= '9') || last == 'X'
}

func isPhoneAccount(s string) bool {
	if len(s) != 11 {
		return false
	}
	if s[0] != '1' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func (s *SettingsStore) RegisterBinanceUser(account, password string, allowEmail, allowPhone bool) (平台用户, []平台用户, error) {
	cfg, err := s.Load()
	if err != nil {
		return 平台用户{}, nil, err
	}
	account = strings.TrimSpace(strings.ToLower(account))
	password = strings.TrimSpace(password)
	if account == "" {
		return 平台用户{}, nil, fmt.Errorf("邮箱/手机号不能为空")
	}
	if len(password) < 8 {
		return 平台用户{}, nil, fmt.Errorf("密码至少8位")
	}
	isEmail := strings.Contains(account, "@")
	isPhone := isPhoneAccount(account)
	if isEmail && !allowEmail {
		return 平台用户{}, nil, fmt.Errorf("系统已关闭邮箱注册")
	}
	if isPhone && !allowPhone {
		return 平台用户{}, nil, fmt.Errorf("系统已关闭手机号注册")
	}
	if !isEmail && !isPhone {
		return 平台用户{}, nil, fmt.Errorf("请输入有效邮箱或手机号")
	}
	for _, u := range cfg.用户列表 {
		if isEmail && strings.EqualFold(strings.TrimSpace(u.邮箱), account) {
			return 平台用户{}, nil, fmt.Errorf("该邮箱已注册，请直接登录")
		}
		if isPhone && strings.TrimSpace(u.手机号) == account {
			return 平台用户{}, nil, fmt.Errorf("该手机号已注册，请直接登录")
		}
	}
	user := 平台用户{
		用户ID:  fmt.Sprintf("usr_%d", time.Now().UnixNano()),
		用户名:   account,
		实名姓名:  "",
		邮箱:    "",
		手机号:   "",
		身份证号:  "",
		角色:    "普通用户",
		登录方式:  "币安风格登录",
		钱包地址:  "",
		启用多因素: true,
		状态:    "启用",
		备注:    "Binance风格注册",
		创建时间:  time.Now().Format(time.RFC3339),
		密码哈希:  hashPassword(password),
		KYC状态: "pending",
	}
	if isEmail {
		user.邮箱 = account
	}
	if isPhone {
		user.手机号 = account
	}
	cfg.用户列表 = append(cfg.用户列表, user)
	if err := s.Save(cfg); err != nil {
		return 平台用户{}, nil, err
	}
	return user, cfg.用户列表, nil
}

func (s *SettingsStore) FindUserByAccount(account string) (平台用户, error) {
	cfg, err := s.Load()
	if err != nil {
		return 平台用户{}, err
	}
	account = strings.TrimSpace(strings.ToLower(account))
	for _, u := range cfg.用户列表 {
		if strings.EqualFold(strings.TrimSpace(u.邮箱), account) || strings.TrimSpace(u.手机号) == account {
			return u, nil
		}
	}
	return 平台用户{}, fmt.Errorf("账号不存在")
}

func (s *SettingsStore) VerifyBinancePassword(account, password string) (平台用户, error) {
	u, err := s.FindUserByAccount(account)
	if err != nil {
		return 平台用户{}, err
	}
	if strings.TrimSpace(u.密码哈希) == "" {
		return 平台用户{}, fmt.Errorf("该账号未设置密码")
	}
	if !verifyPassword(u.密码哈希, password) {
		return 平台用户{}, fmt.Errorf("账号或密码错误")
	}
	return u, nil
}

func (s *SettingsStore) SubmitKYC(account, realName, idCard, front, back, selfie string) (平台用户, []平台用户, error) {
	cfg, err := s.Load()
	if err != nil {
		return 平台用户{}, nil, err
	}
	account = strings.TrimSpace(strings.ToLower(account))
	realName = strings.TrimSpace(realName)
	idCard = strings.TrimSpace(strings.ToUpper(idCard))
	front = strings.TrimSpace(front)
	back = strings.TrimSpace(back)
	selfie = strings.TrimSpace(selfie)
	if realName == "" || !isValidIDCard(idCard) || front == "" || back == "" || selfie == "" {
		return 平台用户{}, nil, fmt.Errorf("KYC信息不完整或格式不合法")
	}
	for i := range cfg.用户列表 {
		u := cfg.用户列表[i]
		if strings.EqualFold(strings.TrimSpace(u.邮箱), account) || strings.TrimSpace(u.手机号) == account {
			u.实名姓名 = realName
			u.身份证号 = idCard
			u.证件正面 = front
			u.证件反面 = back
			u.活体自拍 = selfie
			u.KYC状态 = "approved"
			cfg.用户列表[i] = u
			if err := s.Save(cfg); err != nil {
				return 平台用户{}, nil, err
			}
			return u, cfg.用户列表, nil
		}
	}
	return 平台用户{}, nil, fmt.Errorf("账号不存在")
}
