package config

import (
	"database/sql"
	"product/helper"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

func CreateCon() *sql.DB {

	db, err := sql.Open("mysql", "root:@tcp(localhost:3306)/go_product")
	helper.PanicError(err)

	// helper.MigrateUsers(db) // note using firt time runing in code
	// helper.MigratePasien(db) //// note using firt time runing in code

	db.SetMaxIdleConns(10)
	db.SetMaxOpenConns(100)
	db.SetConnMaxIdleTime(5 * time.Minute)
	db.SetConnMaxLifetime(60 * time.Minute)

	return db
}
