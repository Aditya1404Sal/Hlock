package main

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp"
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
	TOTPKey  string
}

type Session struct {
	gorm.Model
	UserID uint
	Token  string `gorm:"uniqueIndex"`
	Expiry time.Time
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
	r.POST("/verify-otp", verifyOTPHandler)
	r.POST("/logout", authMiddleware(), logoutHandler)
	r.GET("/protected", authMiddleware(), protectedHandler)

	r.Run(":8080")
}

func registerHandler(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}
	user.Password = string(hashedPassword)

	if err := db.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User created successfully"})
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

	if user.TOTPKey == "" {
		key, err := generateTOTPKey(user.Email)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate TOTP key"})
			return
		}
		user.TOTPKey = key
		if err := db.Save(&user).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save TOTP key"})
			return
		}
	}

	otp, err := generateTOTP(user.TOTPKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate OTP"})
		return
	}

	if err := sendOTP(user.Email, user.Phone, otp); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send OTP"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "OTP sent to your email/phone"})
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

	if !totp.Validate(otpData.OTPCode, user.TOTPKey) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid OTP"})
		return
	}

	token := generateToken()
	expiryTime := time.Now().Add(24 * time.Hour)
	session := Session{UserID: user.ID, Token: token, Expiry: expiryTime}
	db.Create(&session)

	logActivity(user.ID, "Login")

	c.JSON(http.StatusOK, gin.H{"message": "Login successful", "token": token})
}

func logoutHandler(c *gin.Context) {
	token := c.GetHeader("Authorization")
	db.Where("token = ?", token).Delete(&Session{})
	logActivity(c.GetUint("user_id"), "Logout")
	c.JSON(http.StatusOK, gin.H{"message": "Logout successful"})
}

// Logs all activity accessed through /protected endpoint
func protectedHandler(c *gin.Context) {
	userID := c.GetUint("user_id")
	var user User
	db.First(&user, userID)
	logActivity(userID, "Accessed protected resource")
	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Hello, %s! Your role is %s", user.Username, user.Role)})
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.GetHeader("Authorization")
		var session Session
		if err := db.Where("token = ? AND expiry > ?", token, time.Now()).First(&session).Error; err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
			c.Abort()
			return
		}
		c.Set("user_id", session.UserID)
		c.Next()
	}
}

// Generates a token that has a lifespan of the session, it adds weight to the authmiddleware lol
func generateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base32.StdEncoding.EncodeToString(b)
}

func generateTOTPKey(account_identifier string) (string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "TheCompanyNameGoesHere",
		AccountName: account_identifier,
		Algorithm:   otp.AlgorithmSHA256,
	})
	if err != nil {
		return "", err
	}
	return key.Secret(), nil
}

func generateTOTP(key string) (string, error) {
	return totp.GenerateCode(key, time.Now())
}

func sendOTP(email, phone, otp string) error {
	// Email and sms service yet to be integrated here
	log.Printf("Sending OTP %s to email %s or phone %s\n", otp, email, phone)
	return nil
}

func logActivity(userID uint, action string) {
	db.Create(&ActivityLog{UserID: userID, Action: action})
}

// TODO : write the SAML implementation for the SSO support
// Will need 3rd party access as well as multiple test cases
