package webapp

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/mail"
	"net/smtp"
	"os"
	"strings"
	"sync"
	"time"
)

type UserProfile struct {
	UserID    string `json:"user_id"`
	Name      string `json:"name"`
	LoginType string `json:"login_type"`
	Email     string `json:"email,omitempty"`
	Wallet    string `json:"wallet,omitempty"`
}

type emailCode struct {
	Code    string
	Expires time.Time
}

type walletNonce struct {
	Nonce   string
	Expires time.Time
}

type loginSession struct {
	User      UserProfile
	ExpiresAt time.Time
}

type qrSession struct {
	Token       string
	ExpiresAt   time.Time
	Confirmed   bool
	ConfirmedBy UserProfile
}

type sliderChallenge struct {
	TargetX   int
	MaxX      int
	Expires   time.Time
	ClientIP  string
	UserAgent string
}

type AuthStore struct {
	mu            sync.Mutex
	emailCodes    map[string]emailCode
	registerCodes map[string]emailCode
	binanceCodes  map[string]emailCode
	adminSliders  map[string]sliderChallenge
	users         map[string]UserProfile
	walletUsers   map[string]UserProfile
	nonces        map[string]walletNonce
	sessions      map[string]loginSession
	qr            map[string]qrSession
}

func NewAuthStore() *AuthStore {
	return &AuthStore{
		emailCodes:    make(map[string]emailCode),
		registerCodes: make(map[string]emailCode),
		binanceCodes:  make(map[string]emailCode),
		adminSliders:  make(map[string]sliderChallenge),
		users:         make(map[string]UserProfile),
		walletUsers:   make(map[string]UserProfile),
		nonces:        make(map[string]walletNonce),
		sessions:      make(map[string]loginSession),
		qr:            make(map[string]qrSession),
	}
}

func (s *AuthStore) SendBinanceCode(account, purpose string) (string, bool, error) {
	account = strings.TrimSpace(strings.ToLower(account))
	if account == "" {
		return "", false, fmt.Errorf("账号不能为空")
	}
	code, err := numericCode(6)
	if err != nil {
		return "", false, err
	}
	s.mu.Lock()
	s.binanceCodes[account] = emailCode{
		Code:    code,
		Expires: time.Now().Add(5 * time.Minute),
	}
	s.mu.Unlock()
	// 邮箱尝试真实发送；手机号走调试返回码（当前不接短信网关）。
	if strings.Contains(account, "@") {
		delivered, sendErr := sendEmailOTP(account, code, purpose)
		return code, delivered, sendErr
	}
	return code, false, nil
}

func (s *AuthStore) VerifyBinanceCode(account, code string) error {
	account = strings.TrimSpace(strings.ToLower(account))
	code = strings.TrimSpace(code)
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.binanceCodes[account]
	if !ok || time.Now().After(item.Expires) {
		return fmt.Errorf("验证码已过期，请重新获取")
	}
	if item.Code != code {
		return fmt.Errorf("验证码错误")
	}
	delete(s.binanceCodes, account)
	return nil
}

func (s *AuthStore) NewAdminSliderChallenge(maxX int, clientIP, userAgent string) (string, int, int, error) {
	if maxX < 80 {
		maxX = 260
	}
	token, err := randomToken(12)
	if err != nil {
		return "", 0, 0, err
	}
	// 缺口固定在中右区域，拼图块从左侧滑过去，视觉上更符合常见滑块验证。
	targetX := 120 + randomInt(maxX-160)
	if targetX < 120 {
		targetX = 120
	}
	s.mu.Lock()
	s.adminSliders[token] = sliderChallenge{
		TargetX:   targetX,
		MaxX:      maxX,
		Expires:   time.Now().Add(3 * time.Minute),
		ClientIP:  strings.TrimSpace(clientIP),
		UserAgent: strings.TrimSpace(userAgent),
	}
	s.mu.Unlock()
	return token, targetX, maxX, nil
}

func (s *AuthStore) VerifyAdminSlider(token string, offset, durationMS, traceCount int, clientIP, userAgent string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return fmt.Errorf("验证码不能为空")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.adminSliders[token]
	if !ok || time.Now().After(item.Expires) {
		delete(s.adminSliders, token)
		return fmt.Errorf("验证码已过期，请刷新")
	}
	delete(s.adminSliders, token)
	if strings.TrimSpace(item.ClientIP) != "" && strings.TrimSpace(item.ClientIP) != strings.TrimSpace(clientIP) {
		return fmt.Errorf("滑块挑战来源不匹配，请刷新重试")
	}
	if strings.TrimSpace(item.UserAgent) != "" && strings.TrimSpace(item.UserAgent) != strings.TrimSpace(userAgent) {
		return fmt.Errorf("滑块挑战终端不匹配，请刷新重试")
	}
	if durationMS < 450 {
		return fmt.Errorf("滑动过快，请重试")
	}
	if durationMS > 30000 {
		return fmt.Errorf("滑动超时，请重试")
	}
	if traceCount < 6 {
		return fmt.Errorf("滑动轨迹异常，请重试")
	}
	if offset < 0 || offset > item.MaxX {
		return fmt.Errorf("滑块位置无效")
	}
	// 容差 6px，兼顾不同浏览器缩放与触控误差。
	if abs(offset-item.TargetX) > 6 {
		return fmt.Errorf("滑块校验失败，请重试")
	}
	return nil
}

func (s *AuthStore) SendEmailCode(email string) (string, bool, error) {
	email = strings.TrimSpace(strings.ToLower(email))
	if _, err := mail.ParseAddress(email); err != nil {
		return "", false, fmt.Errorf("邮箱格式不合法")
	}
	s.mu.Lock()
	_, exists := s.users[email]
	s.mu.Unlock()
	if !exists {
		return "", false, fmt.Errorf("邮箱未注册，请先注册")
	}
	code, err := numericCode(6)
	if err != nil {
		return "", false, err
	}
	s.mu.Lock()
	s.emailCodes[email] = emailCode{
		Code:    code,
		Expires: time.Now().Add(5 * time.Minute),
	}
	s.mu.Unlock()
	delivered, sendErr := sendEmailOTP(email, code, "登录验证码")
	return code, delivered, sendErr
}

func (s *AuthStore) SendMFAEmailCode(email string) (string, bool, error) {
	email = strings.TrimSpace(strings.ToLower(email))
	if _, err := mail.ParseAddress(email); err != nil {
		return "", false, fmt.Errorf("邮箱格式不合法")
	}
	code, err := numericCode(6)
	if err != nil {
		return "", false, err
	}
	s.mu.Lock()
	s.emailCodes[email] = emailCode{
		Code:    code,
		Expires: time.Now().Add(5 * time.Minute),
	}
	s.mu.Unlock()
	delivered, sendErr := sendEmailOTP(email, code, "多因素登录验证码")
	return code, delivered, sendErr
}

func (s *AuthStore) VerifyMFAEmailCode(email, code string) error {
	email = strings.TrimSpace(strings.ToLower(email))
	code = strings.TrimSpace(code)
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.emailCodes[email]
	if !ok || time.Now().After(item.Expires) {
		return fmt.Errorf("邮箱验证码已过期，请重新获取")
	}
	if item.Code != code {
		return fmt.Errorf("邮箱验证码错误")
	}
	delete(s.emailCodes, email)
	return nil
}

func (s *AuthStore) SeedUsers(users []平台用户) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range users {
		email := strings.TrimSpace(strings.ToLower(u.邮箱))
		wallet := strings.TrimSpace(strings.ToLower(u.钱包地址))
		if strings.TrimSpace(u.状态) == "停用" {
			continue
		}
		name := strings.TrimSpace(u.实名姓名)
		if name == "" {
			name = strings.TrimSpace(u.用户名)
		}
		profile := UserProfile{
			UserID:    strings.TrimSpace(u.用户ID),
			Name:      name,
			LoginType: "mfa",
			Email:     email,
			Wallet:    wallet,
		}
		if email != "" {
			s.users[email] = profile
		}
		if wallet != "" {
			s.walletUsers[wallet] = profile
		}
	}
}

func (s *AuthStore) ReplaceUsers(users []平台用户) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users = make(map[string]UserProfile)
	s.walletUsers = make(map[string]UserProfile)
	for _, u := range users {
		email := strings.TrimSpace(strings.ToLower(u.邮箱))
		wallet := strings.TrimSpace(strings.ToLower(u.钱包地址))
		if strings.TrimSpace(u.状态) == "停用" {
			continue
		}
		name := strings.TrimSpace(u.实名姓名)
		if name == "" {
			name = strings.TrimSpace(u.用户名)
		}
		profile := UserProfile{
			UserID:    strings.TrimSpace(u.用户ID),
			Name:      name,
			LoginType: "mfa",
			Email:     email,
			Wallet:    wallet,
		}
		if email != "" {
			s.users[email] = profile
		}
		if wallet != "" {
			s.walletUsers[wallet] = profile
		}
	}
}

func (s *AuthStore) SendRegisterCode(email string) (string, bool, error) {
	email = strings.TrimSpace(strings.ToLower(email))
	if _, err := mail.ParseAddress(email); err != nil {
		return "", false, fmt.Errorf("邮箱格式不合法")
	}
	s.mu.Lock()
	_, exists := s.users[email]
	s.mu.Unlock()
	if exists {
		return "", false, fmt.Errorf("该邮箱已注册，请直接登录")
	}
	code, err := numericCode(6)
	if err != nil {
		return "", false, err
	}
	s.mu.Lock()
	s.registerCodes[email] = emailCode{
		Code:    code,
		Expires: time.Now().Add(10 * time.Minute),
	}
	s.mu.Unlock()
	delivered, sendErr := sendEmailOTP(email, code, "注册验证码")
	return code, delivered, sendErr
}

func (s *AuthStore) SendWeb3RegisterCode(email string) (string, bool, error) {
	email = strings.TrimSpace(strings.ToLower(email))
	if _, err := mail.ParseAddress(email); err != nil {
		return "", false, fmt.Errorf("邮箱格式不合法")
	}
	code, err := numericCode(6)
	if err != nil {
		return "", false, err
	}
	s.mu.Lock()
	s.registerCodes[email] = emailCode{
		Code:    code,
		Expires: time.Now().Add(10 * time.Minute),
	}
	s.mu.Unlock()
	delivered, sendErr := sendEmailOTP(email, code, "Web3实名注册验证码")
	return code, delivered, sendErr
}

func (s *AuthStore) RegisterByCode(email, code, name string) (UserProfile, error) {
	email = strings.TrimSpace(strings.ToLower(email))
	code = strings.TrimSpace(code)
	name = strings.TrimSpace(name)
	if name == "" {
		name = email
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.registerCodes[email]
	if !ok || time.Now().After(item.Expires) {
		return UserProfile{}, fmt.Errorf("注册验证码已过期，请重新获取")
	}
	if item.Code != code {
		return UserProfile{}, fmt.Errorf("注册验证码错误")
	}
	delete(s.registerCodes, email)
	if _, exists := s.users[email]; exists {
		return UserProfile{}, fmt.Errorf("该邮箱已注册，请直接登录")
	}
	user := UserProfile{
		UserID:    "email_" + safeID(email),
		Name:      name,
		LoginType: "email",
		Email:     email,
	}
	s.users[email] = user
	return user, nil
}

func (s *AuthStore) VerifyRegisterCode(email, code string) error {
	email = strings.TrimSpace(strings.ToLower(email))
	code = strings.TrimSpace(code)
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.registerCodes[email]
	if !ok || time.Now().After(item.Expires) {
		return fmt.Errorf("注册验证码已过期，请重新获取")
	}
	if item.Code != code {
		return fmt.Errorf("注册验证码错误")
	}
	delete(s.registerCodes, email)
	if _, exists := s.users[email]; exists {
		return fmt.Errorf("该邮箱已注册，请直接登录")
	}
	return nil
}

func (s *AuthStore) VerifyWeb3RegisterCode(email, code string) error {
	email = strings.TrimSpace(strings.ToLower(email))
	code = strings.TrimSpace(code)
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.registerCodes[email]
	if !ok || time.Now().After(item.Expires) {
		return fmt.Errorf("注册验证码已过期，请重新获取")
	}
	if item.Code != code {
		return fmt.Errorf("注册验证码错误")
	}
	delete(s.registerCodes, email)
	return nil
}

func (s *AuthStore) verifyWeb3SignatureLocked(address, nonce, signature string) error {
	item, ok := s.nonces[address]
	if !ok || time.Now().After(item.Expires) {
		return fmt.Errorf("签名挑战已过期，请重新发起")
	}
	if item.Nonce != nonce {
		return fmt.Errorf("Nonce 不匹配")
	}
	if signature == "" || len(signature) < 20 {
		return fmt.Errorf("签名无效")
	}
	delete(s.nonces, address)
	return nil
}

func (s *AuthStore) VerifyWeb3Signature(address, nonce, signature string) error {
	address = strings.TrimSpace(strings.ToLower(address))
	nonce = strings.TrimSpace(nonce)
	signature = strings.TrimSpace(signature)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.verifyWeb3SignatureLocked(address, nonce, signature)
}

func (s *AuthStore) VerifyEmailCode(email, code string) (UserProfile, error) {
	email = strings.TrimSpace(strings.ToLower(email))
	code = strings.TrimSpace(code)
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.emailCodes[email]
	if !ok || time.Now().After(item.Expires) {
		return UserProfile{}, fmt.Errorf("验证码已过期，请重新获取")
	}
	if item.Code != code {
		return UserProfile{}, fmt.Errorf("验证码错误")
	}
	delete(s.emailCodes, email)
	user, ok := s.users[email]
	if !ok {
		return UserProfile{}, fmt.Errorf("邮箱未注册，请先注册")
	}
	return user, nil
}

func (s *AuthStore) NewWeb3Challenge(address string) (string, string, error) {
	address = strings.TrimSpace(strings.ToLower(address))
	if address == "" {
		return "", "", fmt.Errorf("钱包地址不能为空")
	}
	nonce, err := randomToken(12)
	if err != nil {
		return "", "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nonces[address] = walletNonce{
		Nonce:   nonce,
		Expires: time.Now().Add(5 * time.Minute),
	}
	msg := fmt.Sprintf("研发安全智能管理平台登录签名\n地址: %s\nNonce: %s\n时间: %s", address, nonce, time.Now().Format(time.RFC3339))
	return nonce, msg, nil
}

func (s *AuthStore) VerifyWeb3(address, nonce, signature string) (UserProfile, error) {
	address = strings.TrimSpace(strings.ToLower(address))
	nonce = strings.TrimSpace(nonce)
	signature = strings.TrimSpace(signature)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.verifyWeb3SignatureLocked(address, nonce, signature); err != nil {
		return UserProfile{}, err
	}
	user, ok := s.walletUsers[address]
	if !ok {
		return UserProfile{}, fmt.Errorf("钱包地址未注册，请先在系统中登记用户")
	}
	user.LoginType = "web3"
	user.Wallet = address
	return user, nil
}

func (s *AuthStore) HasEmailUser(email string) bool {
	email = strings.TrimSpace(strings.ToLower(email))
	if email == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.users[email]
	return ok
}

func (s *AuthStore) HasWalletUser(address string) bool {
	address = strings.TrimSpace(strings.ToLower(address))
	if address == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.walletUsers[address]
	return ok
}

func (s *AuthStore) CreateSession(user UserProfile) (string, error) {
	token, err := randomToken(24)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[token] = loginSession{
		User:      user,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	return token, nil
}

func (s *AuthStore) GetSession(token string) (UserProfile, bool) {
	token = strings.TrimSpace(token)
	if token == "" {
		return UserProfile{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sn, ok := s.sessions[token]
	if !ok || time.Now().After(sn.ExpiresAt) {
		delete(s.sessions, token)
		return UserProfile{}, false
	}
	return sn.User, true
}

func (s *AuthStore) DeleteSession(token string) {
	token = strings.TrimSpace(token)
	if token == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, token)
}

func (s *AuthStore) DeleteAllSessions() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions = make(map[string]loginSession)
}

func (s *AuthStore) CreateQRSession() (string, error) {
	token, err := randomToken(18)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.qr[token] = qrSession{
		Token:     token,
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	return token, nil
}

func (s *AuthStore) ConfirmQR(token string, user UserProfile) error {
	token = strings.TrimSpace(token)
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.qr[token]
	if !ok || time.Now().After(item.ExpiresAt) {
		return fmt.Errorf("二维码登录会话已过期")
	}
	item.Confirmed = true
	item.ConfirmedBy = user
	s.qr[token] = item
	return nil
}

func (s *AuthStore) ConsumeQR(token string) (UserProfile, bool, error) {
	token = strings.TrimSpace(token)
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.qr[token]
	if !ok || time.Now().After(item.ExpiresAt) {
		delete(s.qr, token)
		return UserProfile{}, false, fmt.Errorf("二维码登录会话已过期")
	}
	if !item.Confirmed {
		return UserProfile{}, false, nil
	}
	delete(s.qr, token)
	return item.ConfirmedBy, true, nil
}

func randomToken(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func randomInt(max int) int {
	if max <= 0 {
		return 0
	}
	b := make([]byte, 2)
	if _, err := rand.Read(b); err != nil {
		return 0
	}
	v := int(b[0])<<8 | int(b[1])
	if v < 0 {
		v = -v
	}
	return v % max
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

func numericCode(n int) (string, error) {
	if n <= 0 {
		n = 6
	}
	raw, err := randomToken(n)
	if err != nil {
		return "", err
	}
	out := make([]byte, 0, n)
	for i := 0; i < len(raw) && len(out) < n; i++ {
		c := raw[i]
		if c >= '0' && c <= '9' {
			out = append(out, c)
		}
	}
	for len(out) < n {
		out = append(out, '7')
	}
	return string(out), nil
}

func alphaNumCode(n int) (string, error) {
	if n <= 0 {
		n = 5
	}
	raw, err := randomToken(n * 2)
	if err != nil {
		return "", err
	}
	out := make([]byte, 0, n)
	for i := 0; i < len(raw) && len(out) < n; i++ {
		c := raw[i]
		if c >= '0' && c <= '9' {
			out = append(out, c)
			continue
		}
		if c >= 'a' && c <= 'f' {
			out = append(out, byte(c-'a'+'A'))
		}
	}
	for len(out) < n {
		out = append(out, '8')
	}
	return string(out), nil
}

func safeID(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "@", "_")
	s = strings.ReplaceAll(s, ".", "_")
	s = strings.ReplaceAll(s, ":", "_")
	s = strings.ReplaceAll(s, "/", "_")
	return s
}

func sendEmailOTP(toEmail, code, purpose string) (bool, error) {
	host := strings.TrimSpace(os.Getenv("SMTP_HOST"))
	port := strings.TrimSpace(os.Getenv("SMTP_PORT"))
	user := strings.TrimSpace(os.Getenv("SMTP_USER"))
	pass := strings.TrimSpace(os.Getenv("SMTP_PASS"))
	from := strings.TrimSpace(os.Getenv("SMTP_FROM"))

	if host == "" || port == "" || user == "" || pass == "" || from == "" {
		return false, nil
	}
	addr := host + ":" + port
	auth := smtp.PlainAuth("", user, pass, host)
	subject := "研发安全智能管理平台 " + purpose
	body := fmt.Sprintf("您好，\n\n您的%s为：%s\n有效期：5分钟。\n\n如非本人操作请忽略。", purpose, code)
	msg := []byte("To: " + toEmail + "\r\n" +
		"From: " + from + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=UTF-8\r\n\r\n" +
		body)
	if err := smtp.SendMail(addr, auth, from, []string{toEmail}, msg); err != nil {
		return false, err
	}
	return true, nil
}
