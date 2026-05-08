package main

import (
	"database/sql"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB

func InitDB() {
	var err error
	db, err = sql.Open("sqlite3", "./traffic.db")
	if err != nil {
		log.Fatal(err)
	}

	createTableSQL := `CREATE TABLE IF NOT EXISTS traffic (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		method TEXT,
		url TEXT,
		request_body TEXT,
		response_status INTEGER,
		response_body_size INTEGER,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
	);`

	_, err = db.Exec(createTableSQL)
	if err != nil {
		log.Fatal(err)
	}
}

func SaveTraffic(data TrafficData) {
	insertSQL := `INSERT INTO traffic (method, url, request_body, response_status, response_body_size) VALUES (?, ?, ?, ?, ?)`
	_, err := db.Exec(insertSQL, data.Method, data.URL, data.RequestBody, data.ResponseStatus, data.ResponseBodySize)
	if err != nil {
		log.Printf("Error saving traffic to DB: %v", err)
	}
}
