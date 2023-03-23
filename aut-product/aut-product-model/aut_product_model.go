package autproductmodel

import (
	"database/sql"
	"product/config"
	"product/entities"
	"product/helper"
)

func Login(user *entities.Users, username, password string) error {
	con := config.CreateCon()

	script := "SELECT * from users where username = ?"

	err := con.QueryRow(script, username).Scan(
		&user.Id, &user.Name, &user.Email, &user.Username, &user.Password,
	)
	if err != nil {
		return err
	}

	if err == sql.ErrNoRows {
		return err
	}

	match, err := helper.CheckPasswordHash(password, user.Password)
	if !match {
		return err
	}

	return nil
}

func Register(user *entities.Users) error {

	con := config.CreateCon()

	script := "insert into users(name, email, username, password) values(?, ?, ?, ?)"

	stm, err := con.Prepare(script)
	helper.PanicError(err)

	rows, err := stm.Exec(user.Name, user.Email, user.Username, user.Password)
	helper.PanicError(err)

	res, err := rows.LastInsertId()
	user.Id = res

	return nil
}

func Unic(user entities.Users, value, param string) bool {
	con := config.CreateCon()

	script := "SELECT * from users where " + param + " = ?"

	err := con.QueryRow(script, value).Scan(
		&user.Id, &user.Name, &user.Email, &user.Username, &user.Password,
	)
	if err != nil {
		return false
	}

	if err == sql.ErrNoRows {
		return false
	}

	return true
}
