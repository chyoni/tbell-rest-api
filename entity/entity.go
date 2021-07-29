package entity

import (
	"crypto/sha256"
	"fmt"

	"gorm.io/gorm"
)

// User is struct of database user table.
type User struct {
	gorm.Model
	Username       string `gorm:"not null;unique"`
	Password       string `gorm:"not null"`
	FirstName      string
	LastName       string
	Gender         string `gorm:"not null"`
	WorkExperience string
	IsLogged       bool `gorm:"not null;default:false"`
}

// BeforeCreate is receiver function of hashed password.
func (u *User) BeforeCreate(tx *gorm.DB) error {
	passwordAsBytes := []byte(u.Password)
	hashedPassword := sha256.Sum256(passwordAsBytes)
	hexPassword := fmt.Sprintf("%x", hashedPassword)
	u.Password = hexPassword
	return nil
}
