package main

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/xml"
	"fmt"
	"net/http"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/gin-gonic/gin"
)

// SAMLConfig holds the configuration for SAML SSO
type SAMLConfig struct {
	IDPMetadataURL    string
	EntityID          string
	AssertionConsumer string
	Certificate       string
	PrivateKey        string
}

var samlMiddleware *samlsp.Middleware

// initializeSAML sets up SAML middleware
func initializeSAML(config SAMLConfig) error {
	// Parse certificate and private key
	cert, err := tls.X509KeyPair([]byte(config.Certificate), []byte(config.PrivateKey))
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %v", err)
	}
	keyPair := &saml.KeyPair{Key: cert.PrivateKey.(*rsa.PrivateKey), Cert: cert.Certificate[0].(*x509.Certificate)}

	// Fetch IdP metadata
	idpMetadata, err := samlsp.FetchMetadata(http.DefaultClient, config.IDPMetadataURL)
	if err != nil {
		return fmt.Errorf("failed to fetch IdP metadata: %v", err)
	}

	// Create SAML middleware
	opts := samlsp.Options{
		EntityID:          config.EntityID,
		URL:               config.AssertionConsumer,
		Key:               keyPair.Key,
		Certificate:       keyPair.Cert,
		IDPMetadata:       idpMetadata,
		AllowIDPInitiated: true,
	}

	middleware, err := samlsp.New(opts)
	if err != nil {
		return fmt.Errorf("failed to create SAML middleware: %v", err)
	}

	samlMiddleware = middleware
	return nil
}

// SAMLMiddleware wraps the SAML middleware for Gin
func SAMLMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		session, err := samlMiddleware.Session.GetSession(c.Request)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "SAML authentication required"})
			c.Abort()
			return
		}

		if session == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid SAML session"})
			c.Abort()
			return
		}

		samlAttributes := session.(samlsp.SessionIndex).GetAttributes()
		userEmail := samlAttributes.Get("email")

		// Find or create user based on SAML attributes
		var user User
		result := db.Where("email = ?", userEmail).First(&user)
		if result.Error != nil {
			// Create new user if not found
			user = User{
				Email:    userEmail,
				Username: samlAttributes.Get("username"),
				Role:     samlAttributes.Get("role"),
			}
			if err := db.Create(&user).Error; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
				c.Abort()
				return
			}
		}

		// Create session
		token := generateToken()
		expiryTime := time.Now().Add(24 * time.Hour)
		session = Session{UserID: user.ID, Token: token, Expiry: expiryTime}
		db.Create(&session)

		logActivity(user.ID, "SAML Login")

		c.Set("user_id", user.ID)
		c.Next()
	}
}

// Add these routes to your main function
func addSAMLRoutes(r *gin.Engine) {
	samlGroup := r.Group("/saml")
	{
		samlGroup.GET("/metadata", handleSAMLMetadata)
		samlGroup.GET("/login", handleSAMLLogin)
		samlGroup.POST("/acs", handleSAMLACS)
	}

	// Add a protected route that uses both SAML and your existing auth
	r.GET("/saml-protected", SAMLMiddleware(), authMiddleware(), func(c *gin.Context) {
		userID := c.GetUint("user_id")
		var user User
		db.First(&user, userID)
		logActivity(userID, "Accessed SAML protected resource")
		c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Hello, %s! You're authenticated via SAML SSO", user.Username)})
	})
}

func handleSAMLMetadata(c *gin.Context) {
	metadata := samlMiddleware.ServiceProvider.Metadata()
	buf, _ := xml.MarshalIndent(metadata, "", "  ")
	c.Header("Content-Type", "application/samlmetadata+xml")
	c.String(http.StatusOK, string(buf))
}

func handleSAMLLogin(c *gin.Context) {
	samlMiddleware.ServeHTTP(c.Writer, c.Request)
}

func handleSAMLACS(c *gin.Context) {
	samlMiddleware.ServeHTTP(c.Writer, c.Request)
}
