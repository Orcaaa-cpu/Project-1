package helper

import "database/sql"

func MigrateUsers(db *sql.DB) {
	sql := `
    CREATE TABLE users (
		id int NOT NULL AUTO_INCREMENT,
		name varchar(255) NOT NULL,
		email varchar(255) NOT NULL,
		username varchar(255) NOT NULL,
		password varchar(255) NOT NULL,
		PRIMARY KEY (id)
	) ENGINE = InnoDB;
    `

	_, err := db.Exec(sql)
	PanicError(err)
}

func MigratePasien(db *sql.DB) {
	sql := `
    CREATE TABLE pasiens (
		id int NOT NULL AUTO_INCREMENT,
		nama_lengkap varchar(255) NOT NULL,
		nik varchar(255) NOT NULL,
		jenis_kelamin varchar(255) NOT NULL,
		tempat_lahir varchar(255) NOT NULL,
		tanggal_lahir varchar(255) NOT NULL,
		alamat varchar(255) NOT NULL,
		no_hp varchar(255) NOT NULL,
		PRIMARY KEY (id)
	) ENGINE = InnoDB;
    `

	_, err := db.Exec(sql)
	PanicError(err)

}
