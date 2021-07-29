package main

import (
	"github.com/chiwon99881/restapi/env"
	"github.com/chiwon99881/restapi/rest"
)

func main() {
	env.Start()
	//db.CreateTable(&entity.User{})
	rest.Start()
}
