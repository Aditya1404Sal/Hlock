package main

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Username string `gorm:"uniqueIndex"`
	Email    string
	Phone    string
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

func registerHandler(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	user.Password = string(hashedPassword)

	if err := db.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User created"})
}

func loginHandler(c *gin.Context) {
	var loginData struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&loginData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user User
	if err := db.Where("username = ?", loginData.Username).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginData.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Generate OTP and send it to the user's email or phone (tbd)
	otp, err := generateAndSendOTP(user.Email, user.Phone)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate OTP"})
		return
	}

	// Temporarily save otp to users record.
	user.OTPKey = otp
	db.Save(&user)

	c.JSON(http.StatusOK, gin.H{"message": "OTP sent to your email/phone"})
}

func logoutHandler(c *gin.Context) {
	token := c.GetHeader("Authorization")
	db.Where("token = ?", token).Delete(&Session{})
	logActivity(c.GetUint("user_id"), "Logout")
	c.JSON(http.StatusOK, gin.H{"message": "Logout successful"})
}

func verifyOTPHandler(c *gin.Context) {
	var otpData struct {
		Username string `json:"username"`
		OTPCode  string `json:"otp_code"`
	}

	if err := c.ShouldBindJSON(&otpData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user User
	if err := db.Where("username = ?", otpData.Username).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user"})
		return
	}

	if !totp.Validate(otpData.OTPCode, user.OTPKey) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid OTP"})
		return
	}
	//clear the temp otp.
	user.OTPKey = ""
	db.Save(&user)

	token := generateToken()
	session := Session{UserID: user.ID, Token: token}
	db.Create(&session)

	logActivity(user.ID, "Login")

	c.JSON(http.StatusOK, gin.H{"message": "OTP verified", "token": token})
}

func generateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base32.StdEncoding.EncodeToString(b)
}

func generateAndSendOTP(email, phone string) (string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "AdityasCompany",
		AccountName: email + phone,
	})
	if err != nil {
		return "", err
	}

	otp := key.Secret()
	// Actual  OTP sending functionality TBD.
	fmt.Printf("Sending OTP %s to email %s or phone %s\n", otp, email, phone)

	return otp, nil
}

func logActivity(userID uint, action string) {
	db.Create(&ActivityLog{UserID: userID, Action: action})
}
