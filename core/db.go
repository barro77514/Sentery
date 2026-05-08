package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"log"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB
var trafficChan chan TrafficData

func InitDB() {
	var err error
	db, err = sql.Open("sqlite3", "./traffic.db")
	if err != nil {
		log.Fatal(err)
	}

	// Standard traffic logs table
	createRequestsTable := `CREATE TABLE IF NOT EXISTS requests (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		method TEXT,
		url TEXT,
		headers TEXT,
		body BLOB,
		response_status INTEGER,
		response_body_size INTEGER,
		fingerprint TEXT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
	);`

	// Knowledge base for confirmed vulnerabilities
	createKBTable := `CREATE TABLE IF NOT EXISTS knowledge_base (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		vulnerability_type TEXT,
		payload TEXT,
		fingerprint TEXT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
	);`

	_, err = db.Exec(createRequestsTable)
	if err != nil {
		log.Fatal(err)
	}

	_, err = db.Exec(createKBTable)
	if err != nil {
		log.Fatal(err)
	}

	// Indices
	db.Exec("CREATE INDEX IF NOT EXISTS idx_requests_url ON requests(url);")
	db.Exec("CREATE INDEX IF NOT EXISTS idx_requests_fingerprint ON requests(fingerprint);")

	// Initialize channel for async saving
	trafficChan = make(chan TrafficData, 100)
	go processTrafficQueue()

	// Start TTL cleanup routine
	go startCleanupRoutine()
}

func GenerateFingerprint(method, url, body string) string {
	h := sha256.New()
	h.Write([]byte(method + url + body))
	return hex.EncodeToString(h.Sum(nil))
}

func processTrafficQueue() {
	for data := range trafficChan {
		headersJSON, _ := json.Marshal(data.Headers)
		fingerprint := GenerateFingerprint(data.Method, data.URL, data.RequestBody)

		insertSQL := `INSERT INTO requests (method, url, headers, body, response_status, response_body_size, fingerprint)
					  VALUES (?, ?, ?, ?, ?, ?, ?)`
		_, err := db.Exec(insertSQL, data.Method, data.URL, string(headersJSON), []byte(data.RequestBody), data.ResponseStatus, data.ResponseBodySize, fingerprint)
		if err != nil {
			log.Printf("Error saving traffic to DB: %v", err)
		}
	}
}

func SaveTrafficAsync(data TrafficData) {
	trafficChan <- data
}

func startCleanupRoutine() {
	ticker := time.NewTicker(1 * time.Hour)
	for range ticker.C {
		log.Println("Running DB cleanup...")
		_, err := db.Exec("DELETE FROM requests WHERE timestamp < datetime('now', '-24 hours')")
		if err != nil {
			log.Printf("Error during DB cleanup: %v", err)
		}
	}
}
