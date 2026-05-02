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

	// Добавляем бесплатный ключ "Free" если его нет
	_, err = db.Exec(`INSERT OR IGNORE INTO licenses (key, plan, created_at, active, note) VALUES (?, ?, ?, ?, ?)`,
		"Free", "free", time.Now().Format(time.RFC3339), 1, "Бесплатная версия для всех")
	if err != nil {
		log.Fatal(err)
	}

	// Статические файлы
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	http.HandleFunc("/", serveIndex)
	http.HandleFunc("/admin", serveAdmin)

	// API
	http.HandleFunc("/api/validate", handleValidate)
	http.HandleFunc("/api/admin/generate", withAuth(handleGenerate))
	http.HandleFunc("/api/admin/keys", withAuth(handleListKeys))
	http.HandleFunc("/api/admin/revoke", withAuth(handleRevoke))
	http.HandleFunc("/api/admin/reset-hwid", withAuth(handleResetHWID))

	log.Printf("Server running on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

// ── Страницы ──────────────────────────────────────────────────────────────────

func serveIndex(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "static/index.html")
}

func serveAdmin(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "static/admin.html")
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
