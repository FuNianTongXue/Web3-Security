package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
    sqlite "github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

type Product struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Category    string    `json:"category"`
	UpdatedAt   time.Time `json:"updatedAt"`
	CreatedAt   time.Time `json:"createdAt"`
}

type ContactInfo struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Email     string    `json:"email"`
	GithubURL string    `json:"githubUrl"`
	WechatID  string    `json:"wechatId"`
	WechatQR  string    `json:"wechatQrUrl"`
	UpdatedAt time.Time `json:"updatedAt"`
	CreatedAt time.Time `json:"createdAt"`
}

type Setting struct {
	ID        uint      `gorm:"primaryKey" json:"-"`
	Key       string    `gorm:"uniqueIndex" json:"key"`
	Value     string    `json:"value"`
	UpdatedAt time.Time `json:"updatedAt"`
	CreatedAt time.Time `json:"createdAt"`
}

type SiteConfig struct {
	ID        uint      `gorm:"primaryKey" json:"-"`
	JSON      string    `gorm:"type:text" json:"json"`
	UpdatedAt time.Time `json:"updatedAt"`
	CreatedAt time.Time `json:"createdAt"`
}

var (
	db         *gorm.DB
	adminToken string
	dbPath     string
	uploadDir  string
)

func mustEnv(key, def string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	return v
}

func initDB() error {
	var err error
	dbPath = mustEnv("DB_PATH", "/data/app.db")
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		return err
	}
	db, err = gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		return err
	}
	return db.AutoMigrate(&Product{}, &ContactInfo{}, &Setting{}, &SiteConfig{})
}

func seedIfEmpty() error {
	// SiteConfig
	var sc SiteConfig
	if err := db.First(&sc).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		b, err := os.ReadFile("default_site_config.json")
		if err != nil {
			return err
		}
		db.Create(&SiteConfig{JSON: string(b)})
	}

	// Contact
	var c ContactInfo
	if err := db.First(&c).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		db.Create(&ContactInfo{
			Email:     "security@aurumsec.example",
			GithubURL: "https://github.com/your-org",
			WechatID:  "your_wechat_id",
			WechatQR:  "",
		})
	}

	// Settings
	var s Setting
	if err := db.Where("key = ?", "blogEnabled").First(&s).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			db.Create(&Setting{Key: "blogEnabled", Value: "false"})
		} else if err != nil {
			return err
		}
	}

	// Products
	var count int64
	db.Model(&Product{}).Count(&count)
	if count == 0 {
		p := []Product{
			{Name: "安全审计", Description: "Comprehensive audits for smart contracts and L1/L2 chains.", Category: "SECURITY"},
			{Name: "Phalcon 安全监测", Description: "Detect threats, alert what matters, and block attacks in real-time.", Category: "SECURITY"},
			{Name: "Phalcon 合规", Description: "Identify illicit activities and manage risk for AML/CFT compliance.", Category: "COMPLIANCE"},
			{Name: "仿真 API", Description: "签名/发送前预览结果与余额变化。", Category: "TOOLS"},
		}
		db.Create(&p)
	}
	return nil
}

func main() {
	adminToken = mustEnv("ADMIN_TOKEN", "change-me-please")
	uploadDir = mustEnv("UPLOAD_DIR", "/uploads")

	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		panic(err)
	}
	if err := initDB(); err != nil {
		panic(err)
	}
	if err := seedIfEmpty(); err != nil {
		panic(err)
	}

	r := gin.Default()
	r.Use(cors())
	r.Static("/uploads", uploadDir)

	// public
	r.GET("/api/site-config", getSiteConfig)
	r.GET("/api/products", getProducts)
	r.GET("/api/contact", getContact)
	r.GET("/api/settings", getSettings)

	// admin
	admin := r.Group("/api/admin")
	admin.Use(requireAdmin())
	{
		admin.PUT("/site-config", putSiteConfig)
		admin.POST("/products", createProduct)
		admin.PUT("/products/:id", updateProduct)
		admin.DELETE("/products/:id", deleteProduct)

		admin.PUT("/contact", putContact)
		admin.PUT("/settings", putSettings)
		admin.POST("/upload", uploadFile)
	}

	log.Println("backend listening on :8080")
	_ = r.Run("0.0.0.0:8080")
}

func cors() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, X-Admin-Token")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	}
}

func requireAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetHeader("X-Admin-Token") != adminToken {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			c.Abort()
			return
		}
		c.Next()
	}
}

// ---- public handlers ----

func getSiteConfig(c *gin.Context) {
	var sc SiteConfig
	if err := db.First(&sc).Error; err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	var obj any
	if err := json.Unmarshal([]byte(sc.JSON), &obj); err != nil {
		c.JSON(500, gin.H{"error": "invalid site-config json"})
		return
	}
	c.JSON(200, obj)
}

func getProducts(c *gin.Context) {
	var products []Product
	if err := db.Order("id asc").Find(&products).Error; err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, products)
}

func getContact(c *gin.Context) {
	var ci ContactInfo
	_ = db.First(&ci).Error
	c.JSON(200, ci)
}

func getSettings(c *gin.Context) {
	var settings []Setting
	_ = db.Find(&settings).Error
	out := map[string]string{}
	for _, s := range settings {
		out[s.Key] = s.Value
	}
	c.JSON(200, out)
}

// ---- admin handlers ----

func putSiteConfig(c *gin.Context) {
	var obj any
	if err := c.BindJSON(&obj); err != nil {
		c.JSON(400, gin.H{"error": "invalid json"})
		return
	}
	raw, err := json.Marshal(obj)
	if err != nil {
		c.JSON(400, gin.H{"error": "cannot marshal"})
		return
	}
	var sc SiteConfig
	if err := db.First(&sc).Error; err != nil {
		db.Create(&SiteConfig{JSON: string(raw)})
	} else {
		sc.JSON = string(raw)
		db.Save(&sc)
	}
	c.JSON(200, gin.H{"ok": true})
}

type productReq struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Category    string `json:"category"`
}

func createProduct(c *gin.Context) {
	var req productReq
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid json"})
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		c.JSON(400, gin.H{"error": "name required"})
		return
	}
	cat := strings.ToUpper(strings.TrimSpace(req.Category))
	if cat == "" {
		cat = "SECURITY"
	}
	p := Product{Name: req.Name, Description: req.Description, Category: cat}
	if err := db.Create(&p).Error; err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, p)
}

func updateProduct(c *gin.Context) {
	var req productReq
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid json"})
		return
	}
	var p Product
	if err := db.First(&p, c.Param("id")).Error; err != nil {
		c.JSON(404, gin.H{"error": "not found"})
		return
	}
	if strings.TrimSpace(req.Name) != "" {
		p.Name = req.Name
	}
	p.Description = req.Description
	if req.Category != "" {
		p.Category = strings.ToUpper(strings.TrimSpace(req.Category))
	}
	if err := db.Save(&p).Error; err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, p)
}

func deleteProduct(c *gin.Context) {
	if err := db.Delete(&Product{}, c.Param("id")).Error; err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"ok": true})
}

type contactReq struct {
	Email     string `json:"email"`
	GithubURL string `json:"githubUrl"`
	WechatID  string `json:"wechatId"`
	WechatQR  string `json:"wechatQrUrl"`
}

func putContact(c *gin.Context) {
	var req contactReq
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid json"})
		return
	}
	var ci ContactInfo
	_ = db.First(&ci).Error
	ci.Email = req.Email
	ci.GithubURL = req.GithubURL
	ci.WechatID = req.WechatID
	ci.WechatQR = req.WechatQR
	if ci.ID == 0 {
		db.Create(&ci)
	} else {
		db.Save(&ci)
	}
	c.JSON(200, ci)
}

func putSettings(c *gin.Context) {
	var req map[string]string
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid json"})
		return
	}
	for k, v := range req {
		var s Setting
		err := db.Where("key = ?", k).First(&s).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			db.Create(&Setting{Key: k, Value: v})
			continue
		}
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		s.Value = v
		db.Save(&s)
	}
	c.JSON(200, gin.H{"ok": true})
}

func uploadFile(c *gin.Context) {
	f, err := c.FormFile("file")
	if err != nil {
		c.JSON(400, gin.H{"error": "file required"})
		return
	}
	ext := strings.ToLower(filepath.Ext(f.Filename))
	if ext == "" {
		ext = ".png"
	}
	name := time.Now().Format("20060102150405") + ext
	dst := filepath.Join(uploadDir, name)
	if err := c.SaveUploadedFile(f, dst); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"url": "/uploads/" + name})
}
