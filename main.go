package main

import (
	"log"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Username string `gorm:"uniqueIndex"`
	Password string
	Role     string
	OTPKey   string
}

type Session struct {
	gorm.Model
	UserID uint
	Token  string `gorm:"uniqueIndex"`
}

type ActivityLog struct {
	gorm.Model
	UserID uint
	Action string
}

var db *gorm.DB

func main() {
	var err error
	db, err = gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}

	db.AutoMigrate(&User{}, &Session{}, &ActivityLog{})

	r := gin.Default()

	r.POST("/register", registerHandler)
	r.POST("/login", loginHandler)
	r.POST("/logout", authMiddleware(), logoutHandler)
	r.POST("/verify-otp", verifyOTPHandler)
	r.GET("/protected", authMiddleware(), protectedHandler)

	r.Run(":8080")
}
