package itemsproductmodels

import (
	"product/config"
	"product/entities"
	"product/helper"
	"time"
)

var con = config.CreateCon()

func GetPasien() ([]entities.Pasiens, error) {

	con := config.CreateCon()

	script := "SELECT * FROM pasiens"

	rows, err := con.Query(script)
	helper.PanicError(err)
	defer rows.Close()

	pasiens := []entities.Pasiens{}

	for rows.Next() {
		pasien := entities.Pasiens{}
		err = rows.Scan(&pasien.Id, &pasien.NamaLengkap, &pasien.NIK, &pasien.JenisKelamin, &pasien.TempatLahir, &pasien.TanggalLahir, &pasien.Alamat, &pasien.NoHp)

		if pasien.JenisKelamin == "1" {
			pasien.JenisKelamin = "Laki-laki"
		} else {
			pasien.JenisKelamin = "Perempuan"
		}

		tgl_lahir, _ := time.Parse("2006-01-02", pasien.TanggalLahir)
		pasien.TanggalLahir = tgl_lahir.Format("02-01-2006")

		pasiens = append(pasiens, pasien)
	}

	return pasiens, nil
}

func CreatePasien(pasien *entities.Pasiens) error {

	script := "insert into pasiens (nama_lengkap, nik, jenis_kelamin, tempat_lahir, tanggal_lahir, alamat, no_hp) values(?,?,?,?,?,?,?)"
	stmt, err := con.Prepare(script)
	helper.PanicError(err)

	result, err := stmt.Exec(pasien.NamaLengkap, pasien.NIK, pasien.JenisKelamin, pasien.TempatLahir, pasien.TanggalLahir, pasien.Alamat, pasien.NoHp)
	helper.PanicError(err)

	pasien.Id, _ = result.LastInsertId()

	return nil
}

func FindId(id int64, pasien *entities.Pasiens) error {

	script := "select * from pasiens where id = ?"

	return con.QueryRow(script, id).Scan(
		&pasien.Id, &pasien.NamaLengkap, &pasien.NIK, &pasien.JenisKelamin, &pasien.TempatLahir, &pasien.TanggalLahir, &pasien.Alamat, &pasien.NoHp,
	)
}

func EditPasien(pasien entities.Pasiens) error {
	script := "update pasiens set nama_lengkap = ?, nik = ?, jenis_kelamin = ?, tempat_lahir = ?, tanggal_lahir = ?, alamat = ?, no_hp = ? where id = ?"

	stmt, _ := con.Prepare(script)
	_, err := stmt.Exec(pasien.NamaLengkap, pasien.NIK, pasien.JenisKelamin, pasien.TempatLahir, pasien.TanggalLahir, pasien.Alamat, pasien.NoHp, pasien.Id)
	helper.PanicError(err)

	return nil
}

func DeletePasien(id int64) {
	con.Exec("delete from pasiens where id = ?", id)
}
