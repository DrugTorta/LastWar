package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

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

	var err error
	db, err = sql.Open("sqlite3", "./licenses.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS licenses (
		key TEXT PRIMARY KEY,
		plan TEXT NOT NULL,
		hwid TEXT,
		created_at TEXT NOT NULL,
		expires_at TEXT,
		active INTEGER DEFAULT 1,
		note TEXT
	)`)
	if err != nil {
		log.Fatal(err)
	}

	// Таблица пользователей
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL,
		license_key TEXT,
		created_at TEXT NOT NULL,
		FOREIGN KEY(license_key) REFERENCES licenses(key)
	)`)
	if err != nil {
		log.Fatal(err)
	}

	// Добавляем бесплатный ключ "Free" если его нет
	_, err = db.Exec(`INSERT OR IGNORE INTO licenses (key, plan, created_at, active, note) VALUES (?, ?, ?, ?, ?)`,
		"Free", "free", time.Now().Format(time.RFC3339), 1, "Бесплатная версия для всех")
	if err != nil {
		log.Fatal(err)
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
		`INSERT INTO users (username, password, created_at) VALUES (?, ?, ?)`,
		req.Username, hashedPassword, time.Now().Format(time.RFC3339),
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
		`SELECT license_key FROM users WHERE username=? AND password=?`,
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
	err := db.QueryRow(`SELECT license_key FROM users WHERE username=?`, username).Scan(&licenseKey)
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
		`SELECT plan, COALESCE(hwid,''), COALESCE(expires_at,''), active FROM licenses WHERE key=?`,
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
	err := db.QueryRow(`SELECT plan, active FROM licenses WHERE key=?`, req.Key).Scan(&plan, &active)
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
	_, err = db.Exec(`UPDATE users SET license_key=? WHERE username=?`, req.Key, req.Username)
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

	if username == "" || key == "" {
		jsonError(w, "Username and key required", http.StatusBadRequest)
		return
	}

	// Проверяем что ключ принадлежит пользователю
	var userKey sql.NullString
	err := db.QueryRow(`SELECT license_key FROM users WHERE username=?`, username).Scan(&userKey)
	if err != nil || !userKey.Valid || userKey.String != key {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Получаем план
	var plan string
	err = db.QueryRow(`SELECT plan FROM licenses WHERE key=?`, key).Scan(&plan)
	if err != nil {
		jsonError(w, "Invalid key", http.StatusNotFound)
		return
	}

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
		
		// Временная заглушка для тестирования
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "Мод для плана %s пока не загружен на сервер.\n", plan)
		fmt.Fprintf(w, "Ожидаемый файл: %s\n", filename)
		fmt.Fprintf(w, "\nСвяжитесь с администратором для загрузки файла.")
		return
	}

	// Устанавливаем заголовки для скачивания
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=LastWar-%s.jar", plan))
	w.Header().Set("Content-Type", "application/java-archive")
	
	log.Printf("Serving file: %s for user: %s", filename, username)
	
	// Отдаем файл
	http.ServeFile(w, r, filename)
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
		`SELECT plan, COALESCE(hwid,''), COALESCE(expires_at,''), active FROM licenses WHERE key=?`,
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
		exp, _ := time.Parse(time.RFC3339, expiresAt)
		if time.Now().After(exp) {
			jsonResponse(w, map[string]any{"valid": false, "reason": "key expired"})
			return
		}
	}

	// HWID привязка (только для платных ключей)
	if plan != "free" {
		if hwid == "" && req.HWID != "" {
			db.Exec(`UPDATE licenses SET hwid=? WHERE key=?`, req.HWID, req.Key)
			hwid = req.HWID
		}
		if hwid != "" && req.HWID != "" && hwid != req.HWID {
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

	var expiresAt *string
	if req.Days > 0 {
		t := time.Now().AddDate(0, 0, req.Days).Format(time.RFC3339)
		expiresAt = &t
	} else if req.Days == -1 {
		// Тестовый ключ на 2 минуты
		t := time.Now().Add(2 * time.Minute).Format(time.RFC3339)
		expiresAt = &t
	}

	keys := make([]string, 0, req.Count)
	for i := 0; i < req.Count; i++ {
		key := generateKey()
		_, err := db.Exec(
			`INSERT INTO licenses (key, plan, created_at, expires_at, note) VALUES (?,?,?,?,?)`,
			key, req.Plan, time.Now().Format(time.RFC3339), expiresAt, req.Note,
		)
		if err == nil {
			keys = append(keys, key)
		}
	}

	jsonResponse(w, map[string]any{"keys": keys})
}

// ── API: Список ключей ────────────────────────────────────────────────────────

func handleListKeys(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(`SELECT key, plan, COALESCE(hwid,''), created_at, COALESCE(expires_at,''), active, COALESCE(note,'') FROM licenses ORDER BY created_at DESC`)
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
	db.Exec(`UPDATE licenses SET active=0 WHERE key=?`, req.Key)
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
	db.Exec(`UPDATE licenses SET hwid='' WHERE key=?`, req.Key)
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
