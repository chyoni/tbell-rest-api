package db

import (
	"fmt"
	"os"

	"github.com/chiwon99881/restapi/entity"
	"github.com/chiwon99881/restapi/utility"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// DB is function of get database.
func DB() *gorm.DB {
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable TimeZone=Asia/Seoul",
		os.Getenv("DB_HOST"), os.Getenv("DB_USER"), os.Getenv("DB_PW"), os.Getenv("DB_NAME"), os.Getenv("DB_PORT"))

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	utility.ErrorHandler(err)
	return db
}

// CreateTable is function of create table in database.
func CreateTable(v interface{}) {
	isExists := DB().Migrator().HasTable(v)
	if isExists {
		return
	}
	err := DB().Migrator().CreateTable(v)
	utility.ErrorHandler(err)
}

func IsLoggedIn(userID uint) bool {
	var user = &entity.User{}
	result := DB().Where("id = ?", userID).Find(user)

	if result.RowsAffected == 0 || result.Error != nil {
		utility.ErrorHandler(result.Error)
		return false
	}
	return user.IsLogged
}
