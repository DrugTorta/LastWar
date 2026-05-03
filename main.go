package main

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB
var adminPassword string

func main() {
	adminPassword = os.Getenv("ADMIN_PASSWORD")
	if adminPassword == "" {
		adminPassword = "Fsgfgbff123"
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Подключение к базе данных
	var err error
	
	// Проверяем наличие PostgreSQL (Railway автоматически создает DATABASE_URL)
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL != "" {
		// PostgreSQL (Railway)
		log.Println("Connecting to PostgreSQL...")
		db, err = sql.Open("postgres", databaseURL)
		if err != nil {
			log.Fatal("Failed to connect to PostgreSQL:", err)
		}
		log.Println("✅ PostgreSQL connected successfully")
	} else {
		// SQLite (локальная разработка)
		log.Println("Using SQLite for local development...")
		dbPath := "./database/licenses.db"
		if err := os.MkdirAll("./database", 0755); err != nil {
			log.Fatal("Failed to create database directory:", err)
		}
		db, err = sql.Open("sqlite3", dbPath)
		if err != nil {
			log.Fatal("Failed to open SQLite:", err)
		}
		log.Println("✅ SQLite connected successfully:", dbPath)
	}
	defer db.Close()

	// Проверяем подключение
	if err = db.Ping(); err != nil {
		log.Fatal("Failed to ping database:", err)
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS licenses (
		key TEXT PRIMARY KEY,
		plan TEXT NOT NULL,
		hwid TEXT,
		created_at TIMESTAMP NOT NULL,
		expires_at TIMESTAMP,
		active INTEGER DEFAULT 1,
		note TEXT
	)`)
	if err != nil {
		log.Fatal("Failed to create licenses table:", err)
	}

	// Таблица пользователей
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS users (
		id SERIAL PRIMARY KEY,
		username TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL,
		license_key TEXT,
		created_at TIMESTAMP NOT NULL,
		FOREIGN KEY(license_key) REFERENCES licenses(key)
	)`)
	if err != nil {
		log.Fatal("Failed to create users table:", err)
	}

	// Добавляем бесплатный ключ "Free" если его нет
	_, err = db.Exec(`INSERT INTO licenses (key, plan, created_at, active, note) 
		VALUES ($1, $2, $3, $4, $5) 
		ON CONFLICT (key) DO NOTHING`,
		"Free", "free", time.Now(), 1, "Бесплатная версия для всех")
	if err != nil {
		log.Fatal("Failed to insert Free key:", err)
	}

	// Статические файлы
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	
	// Страницы
	http.HandleFunc("/", serveIndex)
	http.HandleFunc("/admin", serveAdmin)
	http.HandleFunc("/auth.html", serveAuth)
	http.HandleFunc("/dashboard.html", serveDashboard)
	http.HandleFunc("/buy.html", serveBuy)
	http.HandleFunc("/changelog.html", serveChangelog)

	// API
	http.HandleFunc("/api/validate", handleValidate)
	http.HandleFunc("/api/register", handleRegister)
	http.HandleFunc("/api/login", handleLogin)
	http.HandleFunc("/api/user/info", handleUserInfo)
	http.HandleFunc("/api/user/activate", handleActivateKey)
	http.HandleFunc("/api/download", handleDownload)
	http.HandleFunc("/api/admin/generate", withAuth(handleGenerate))
	http.HandleFunc("/api/admin/keys", withAuth(handleListKeys))
	http.HandleFunc("/api/admin/revoke", withAuth(handleRevoke))
	http.HandleFunc("/api/admin/reset-hwid", withAuth(handleResetHWID))

	log.Printf("Server running on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

// ── Страницы ──────────────────────────────────────────────────────────────────

func serveIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, "static/index.html")
}

func serveAdmin(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "static/admin.html")
}

func serveAuth(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "static/auth.html")
}

func serveDashboard(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "static/dashboard.html")
}

func serveBuy(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "static/buy.html")
}

func serveChangelog(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "static/changelog.html")
}

// ── Middleware ────────────────────────────────────────────────────────────────

func withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pass := r.Header.Get("X-Admin-Password")
		if pass != adminPassword {
			jsonError(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// ── API: Регистрация ──────────────────────────────────────────────────────────

func handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Bad request", http.StatusBadRequest)
		return
	}

	req.Username = strings.TrimSpace(req.Username)
	req.Password = strings.TrimSpace(req.Password)

	if req.Username == "" || req.Password == "" {
		jsonError(w, "Username and password required", http.StatusBadRequest)
		return
	}

	// Хешируем пароль (простой способ, для продакшена используйте bcrypt)
	hashedPassword := fmt.Sprintf("%x", []byte(req.Password))

	_, err := db.Exec(
		`INSERT INTO users (username, password, created_at) VALUES ($1, $2, $3)`,
		req.Username, hashedPassword, time.Now(),
	)
	if err != nil {
		jsonError(w, "Username already exists", http.StatusConflict)
		return
	}

	jsonResponse(w, map[string]any{"success": true, "message": "User registered"})
}

// ── API: Логин ────────────────────────────────────────────────────────────────

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Bad request", http.StatusBadRequest)
		return
	}

	hashedPassword := fmt.Sprintf("%x", []byte(req.Password))

	var licenseKey sql.NullString
	err := db.QueryRow(
		`SELECT license_key FROM users WHERE username=$1 AND password=$2`,
		req.Username, hashedPassword,
	).Scan(&licenseKey)

	if err == sql.ErrNoRows {
		jsonError(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}
	if err != nil {
		jsonError(w, "DB error", http.StatusInternalServerError)
		return
	}

	jsonResponse(w, map[string]any{
		"success":     true,
		"username":    req.Username,
		"license_key": licenseKey.String,
	})
}

// ── API: Информация о пользователе ────────────────────────────────────────────

func handleUserInfo(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	if username == "" {
		jsonError(w, "Username required", http.StatusBadRequest)
		return
	}

	var licenseKey sql.NullString
	err := db.QueryRow(`SELECT license_key FROM users WHERE username=$1`, username).Scan(&licenseKey)
	if err == sql.ErrNoRows {
		jsonError(w, "User not found", http.StatusNotFound)
		return
	}
	if err != nil {
		jsonError(w, "DB error", http.StatusInternalServerError)
		return
	}

	if !licenseKey.Valid || licenseKey.String == "" {
		jsonResponse(w, map[string]any{
			"has_license": false,
			"plan":        "none",
		})
		return
	}

	var plan, hwid, expiresAt string
	var active int
	err = db.QueryRow(
		`SELECT plan, COALESCE(hwid,''), COALESCE(expires_at::text,''), active FROM licenses WHERE key=$1`,
		licenseKey.String,
	).Scan(&plan, &hwid, &expiresAt, &active)

	if err != nil {
		jsonError(w, "License not found", http.StatusNotFound)
		return
	}

	jsonResponse(w, map[string]any{
		"has_license": true,
		"license_key": licenseKey.String,
		"plan":        plan,
		"hwid":        hwid,
		"expires_at":  expiresAt,
		"active":      active == 1,
	})
}

// ── API: Активация ключа ──────────────────────────────────────────────────────

func handleActivateKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Key      string `json:"key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Bad request", http.StatusBadRequest)
		return
	}

	req.Key = strings.TrimSpace(req.Key)

	// Проверяем существование ключа
	var plan string
	var active int
	err := db.QueryRow(`SELECT plan, active FROM licenses WHERE key=$1`, req.Key).Scan(&plan, &active)
	if err == sql.ErrNoRows {
		jsonError(w, "Invalid key", http.StatusNotFound)
		return
	}
	if err != nil {
		jsonError(w, "DB error", http.StatusInternalServerError)
		return
	}

	if active == 0 {
		jsonError(w, "Key is revoked", http.StatusForbidden)
		return
	}

	// Привязываем ключ к пользователю
	_, err = db.Exec(`UPDATE users SET license_key=$1 WHERE username=$2`, req.Key, req.Username)
	if err != nil {
		jsonError(w, "Failed to activate key", http.StatusInternalServerError)
		return
	}

	jsonResponse(w, map[string]any{
		"success": true,
		"plan":    plan,
		"key":     req.Key,
	})
}

// ── API: Скачивание мода ──────────────────────────────────────────────────────

func handleDownload(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	key := r.URL.Query().Get("key")

	if key == "" {
		jsonError(w, "Key required", http.StatusBadRequest)
		return
	}

	var plan string
	
	// Для Free версии не требуется авторизация
	if key == "Free" {
		plan = "free"
	} else {
		// Для платных версий проверяем авторизацию
		if username == "" {
			jsonError(w, "Username required", http.StatusBadRequest)
			return
		}

		// Проверяем что ключ принадлежит пользователю
		var userKey sql.NullString
		err := db.QueryRow(`SELECT license_key FROM users WHERE username=$1`, username).Scan(&userKey)
		if err != nil || !userKey.Valid || userKey.String != key {
			jsonError(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Получаем план
		err = db.QueryRow(`SELECT plan FROM licenses WHERE key=$1`, key).Scan(&plan)
		if err != nil {
			jsonError(w, "Invalid key", http.StatusNotFound)
			return
		}
	}

	// Логируем текущую директорию
	cwd, _ := os.Getwd()
	log.Printf("Current working directory: %s", cwd)

	// Определяем файл для скачивания
	var filename string
	switch plan {
	case "free":
		filename = "mods/Free.jar"
	case "paid":
		filename = "mods/Paid.jar"
	case "alpha":
		filename = "mods/Alpha.jar"
	default:
		jsonError(w, "Invalid plan", http.StatusBadRequest)
		return
	}

	// Проверяем существование файла
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		log.Printf("File not found: %s", filename)
		
		// Проверяем что есть в текущей директории
		files, _ := os.ReadDir(".")
		log.Printf("Files in current directory:")
		for _, f := range files {
			log.Printf("  - %s (dir: %v)", f.Name(), f.IsDir())
		}
		
		// Проверяем папку mods если она есть
		if modsFiles, err := os.ReadDir("mods"); err == nil {
			log.Printf("Files in mods directory:")
			for _, f := range modsFiles {
				log.Printf("  - %s", f.Name())
			}
		}
		
		jsonError(w, "Mod file not found on server. Check Railway logs.", http.StatusNotFound)
		return
	}

	// Создаем модифицированный JAR с токеном
	log.Printf("Adding token to JAR: %s", filename)
	modifiedJar, err := addTokenToJar(filename, key)
	if err != nil {
		log.Printf("Error adding token to JAR: %v", err)
		jsonError(w, "Error preparing mod file", http.StatusInternalServerError)
		return
	}
	
	log.Printf("Successfully created modified JAR with token, size: %d bytes", len(modifiedJar))

	// Устанавливаем заголовки для скачивания
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=LastWar-%s.jar", plan))
	w.Header().Set("Content-Type", "application/java-archive")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(modifiedJar)))
	
	log.Printf("Serving modified JAR (size: %d bytes) for user: %s with key: %s", len(modifiedJar), username, key)
	
	// Отдаем модифицированный файл
	w.Write(modifiedJar)
}

// ── Добавление token.txt в JAR ────────────────────────────────────────────────

func addTokenToJar(jarPath string, token string) ([]byte, error) {
	log.Printf("Opening JAR file: %s", jarPath)
	
	// Читаем оригинальный JAR
	jarFile, err := os.Open(jarPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open JAR: %w", err)
	}
	defer jarFile.Close()

	jarInfo, err := jarFile.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to stat JAR: %w", err)
	}
	
	log.Printf("Original JAR size: %d bytes", jarInfo.Size())

	// Читаем JAR как ZIP
	zipReader, err := zip.NewReader(jarFile, jarInfo.Size())
	if err != nil {
		return nil, fmt.Errorf("failed to read JAR as ZIP: %w", err)
	}
	
	log.Printf("JAR contains %d files", len(zipReader.File))

	// Создаем новый ZIP в памяти
	buf := new(bytes.Buffer)
	zipWriter := zip.NewWriter(buf)

	// Копируем все файлы из оригинального JAR
	copiedFiles := 0
	for _, file := range zipReader.File {
		// Пропускаем старый token.txt если он есть
		if file.Name == "token.txt" {
			log.Printf("Skipping existing token.txt")
			continue
		}

		// Копируем файл
		fileReader, err := file.Open()
		if err != nil {
			return nil, fmt.Errorf("failed to open file %s: %w", file.Name, err)
		}

		header := &zip.FileHeader{
			Name:   file.Name,
			Method: file.Method,
		}
		
		writer, err := zipWriter.CreateHeader(header)
		if err != nil {
			fileReader.Close()
			return nil, fmt.Errorf("failed to create header for %s: %w", file.Name, err)
		}

		_, err = io.Copy(writer, fileReader)
		fileReader.Close()
		if err != nil {
			return nil, fmt.Errorf("failed to copy file %s: %w", file.Name, err)
		}
		
		copiedFiles++
	}
	
	log.Printf("Copied %d files from original JAR", copiedFiles)

	// Добавляем token.txt
	log.Printf("Adding token.txt with content: %s", token)
	tokenWriter, err := zipWriter.Create("token.txt")
	if err != nil {
		return nil, fmt.Errorf("failed to create token.txt: %w", err)
	}
	_, err = tokenWriter.Write([]byte(token))
	if err != nil {
		return nil, fmt.Errorf("failed to write token: %w", err)
	}

	// Закрываем ZIP writer
	err = zipWriter.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to close ZIP writer: %w", err)
	}
	
	log.Printf("Successfully created modified JAR, final size: %d bytes", buf.Len())

	return buf.Bytes(), nil
}

// ── API: Валидация ключа (вызывается из мода) ─────────────────────────────────

func handleValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Key  string `json:"key"`
		HWID string `json:"hwid"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Bad request", http.StatusBadRequest)
		return
	}

	req.Key = strings.TrimSpace(req.Key)
	req.HWID = strings.TrimSpace(req.HWID)

	if req.Key == "" {
		jsonResponse(w, map[string]any{"valid": false, "reason": "empty key"})
		return
	}

	// Для Free ключа HWID не проверяется
	if req.Key == "Free" {
		jsonResponse(w, map[string]any{"valid": true, "plan": "free"})
		return
	}

	var plan, hwid, expiresAt string
	var active int
	err := db.QueryRow(
		`SELECT plan, COALESCE(hwid,''), COALESCE(expires_at::text,''), active FROM licenses WHERE key=$1`,
		req.Key,
	).Scan(&plan, &hwid, &expiresAt, &active)

	if err == sql.ErrNoRows {
		jsonResponse(w, map[string]any{"valid": false, "reason": "key not found"})
		return
	}
	if err != nil {
		jsonError(w, "DB error", http.StatusInternalServerError)
		return
	}
	if active == 0 {
		jsonResponse(w, map[string]any{"valid": false, "reason": "key revoked"})
		return
	}

	// Проверка срока
	if expiresAt != "" {
		exp, err := time.Parse(time.RFC3339, expiresAt)
		if err != nil {
			log.Printf("Error parsing expiration date: %v", err)
		} else {
			log.Printf("Key %s expires at: %s (now: %s)", req.Key, exp, time.Now())
			if time.Now().After(exp) {
				jsonResponse(w, map[string]any{"valid": false, "reason": "key expired"})
				return
			}
		}
	}

	// HWID привязка (только для платных ключей)
	if plan != "free" {
		if hwid == "" && req.HWID != "" {
			log.Printf("Binding HWID %s to key %s", req.HWID, req.Key)
			db.Exec(`UPDATE licenses SET hwid=$1 WHERE key=$2`, req.HWID, req.Key)
			hwid = req.HWID
		}
		if hwid != "" && req.HWID != "" && hwid != req.HWID {
			log.Printf("HWID mismatch for key %s: expected %s, got %s", req.Key, hwid, req.HWID)
			jsonResponse(w, map[string]any{"valid": false, "reason": "hwid mismatch"})
			return
		}
	}

	jsonResponse(w, map[string]any{"valid": true, "plan": plan})
}

// ── API: Генерация ключа ──────────────────────────────────────────────────────

func handleGenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Plan    string `json:"plan"`    // basic / premium / lifetime
		Days    int    `json:"days"`    // 0 = бессрочно
		Note    string `json:"note"`
		Count   int    `json:"count"`   // сколько ключей сгенерировать
	}
	json.NewDecoder(r.Body).Decode(&req)

	if req.Plan == "" {
		req.Plan = "basic"
	}
	if req.Count <= 0 {
		req.Count = 1
	}
	if req.Count > 50 {
		req.Count = 50
	}

	var expiresAt *time.Time
	if req.Days > 0 {
		t := time.Now().AddDate(0, 0, req.Days)
		expiresAt = &t
	} else if req.Days == -1 {
		// Тестовый ключ на 2 минуты
		t := time.Now().Add(2 * time.Minute)
		expiresAt = &t
	}

	keys := make([]string, 0, req.Count)
	for i := 0; i < req.Count; i++ {
		key := generateKey()
		_, err := db.Exec(
			`INSERT INTO licenses (key, plan, created_at, expires_at, note) VALUES ($1,$2,$3,$4,$5)`,
			key, req.Plan, time.Now(), expiresAt, req.Note,
		)
		if err == nil {
			keys = append(keys, key)
		}
	}

	jsonResponse(w, map[string]any{"keys": keys})
}

// ── API: Список ключей ────────────────────────────────────────────────────────

func handleListKeys(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(`SELECT key, plan, COALESCE(hwid,''), created_at, COALESCE(expires_at::text,''), active, COALESCE(note,'') FROM licenses ORDER BY created_at DESC`)
	if err != nil {
		jsonError(w, "DB error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type KeyInfo struct {
		Key       string `json:"key"`
		Plan      string `json:"plan"`
		HWID      string `json:"hwid"`
		CreatedAt string `json:"created_at"`
		ExpiresAt string `json:"expires_at"`
		Active    int    `json:"active"`
		Note      string `json:"note"`
	}

	var list []KeyInfo
	for rows.Next() {
		var k KeyInfo
		rows.Scan(&k.Key, &k.Plan, &k.HWID, &k.CreatedAt, &k.ExpiresAt, &k.Active, &k.Note)
		list = append(list, k)
	}
	if list == nil {
		list = []KeyInfo{}
	}
	jsonResponse(w, map[string]any{"keys": list})
}

// ── API: Отозвать ключ ────────────────────────────────────────────────────────

func handleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Key string `json:"key"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	db.Exec(`UPDATE licenses SET active=0 WHERE key=$1`, req.Key)
	jsonResponse(w, map[string]any{"ok": true})
}

// ── API: Сбросить HWID ────────────────────────────────────────────────────────

func handleResetHWID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Key string `json:"key"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	db.Exec(`UPDATE licenses SET hwid='' WHERE key=$1`, req.Key)
	jsonResponse(w, map[string]any{"ok": true})
}

// ── Утилиты ───────────────────────────────────────────────────────────────────

func generateKey() string {
	b := make([]byte, 16)
	rand.Read(b)
	s := strings.ToUpper(hex.EncodeToString(b))
	return fmt.Sprintf("LW-%s-%s-%s-%s", s[0:4], s[4:8], s[8:12], s[12:16])
}

func jsonResponse(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
