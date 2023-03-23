package main

import (
	"product/config"
	"product/routes"
)

func main() {

	config.CreateCon()

	e := routes.Init()

	e.Logger.Fatal(e.Start(":3000"))
}
