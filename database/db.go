package database

import (
	"database/sql"
	"encoding/json"
	"sync"

	"github.com/cassanof/advisory-query/model"
	_ "github.com/mattn/go-sqlite3"
)

type Database struct {
	db *sql.DB
	mu sync.Mutex
}

var DB *Database

const create string = `
  CREATE TABLE IF NOT EXISTS [cache] (
    fullpath TEXT NOT NULL PRIMARY KEY,
    vulns TEXT NOT NULL
	);
`

func InitDB() {
	db, err := sql.Open("sqlite3", "./database/cache.db")
	if err != nil {
		panic(err)
	}
	DB = &Database{db, sync.Mutex{}}

	_, err = DB.db.Exec(create)
	if err != nil {
		panic(err)
	}
}

func (db *Database) Close() {
	db.db.Close()
}

func (db *Database) Insert(fullpath string, vulns []model.Vulnerability) error {
	vulnsJson, err := json.Marshal(vulns)
	if err != nil {
		return err
	}
	DB.mu.Lock()
	_, err = DB.db.Exec("INSERT INTO cache (fullpath, vulns) VALUES (?, ?)", fullpath, string(vulnsJson))
	DB.mu.Unlock()
	if err != nil {
		return err
	}
	return nil
}

func (db *Database) Get(fullpath string) []model.Vulnerability {
	var vulns []model.Vulnerability
	var vulnsJson string
	DB.mu.Lock()
	err := DB.db.QueryRow("SELECT vulns FROM cache WHERE fullpath = ?", fullpath).Scan(&vulnsJson)
	DB.mu.Unlock()
	if err != nil {
		return nil
	}
	err = json.Unmarshal([]byte(vulnsJson), &vulns)
	if err != nil {
		return nil
	}
	return vulns
}
