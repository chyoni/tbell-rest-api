package main

import (
	"github.com/chiwon99881/restapi/db"
	"github.com/chiwon99881/restapi/entity"
	"github.com/chiwon99881/restapi/env"
	"github.com/chiwon99881/restapi/rest"
)

func main() {
	env.Start()
	db.CreateTable(&entity.User{})
	rest.Start()
}
