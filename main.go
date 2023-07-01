package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/google/uuid"
)

var rdb *redis.Client

type User struct {
	UserID   string `json:"userId"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

func main() {
	// Establish Redis connection
	rdb = redis.NewClient(&redis.Options{
		Addr:     "localhost:6379", // Replace with your Redis server address
		Password: "",               // Add password if required
		DB:       0,                // Use the default database
	})

	// Create a new Gin router
	router := gin.Default()

	// Define the routes
	router.POST("/users", createUserHandler)
	router.POST("/login", loginHandler)
  router.GET("/profile/:usernameOrEmail", profileHandler)
  router.POST("/logout", logoutHandler)

	// Start the server
	log.Fatal(router.Run(":8080"))
}

func createUserHandler(c *gin.Context) {
	// Parse request body into User struct
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
		return
	}

	// Check if username already exists
	exists, err := usernameExists(user.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}
	if exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username already exists"})
		return
	}

	// Check if email already exists
	exists, err = emailExists(user.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}
	if exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email already exists"})
		return
	}

	// Generate a new UUID for the user
	user.UserID = uuid.New().String()

	// Encrypt the user's password
	encryptedPassword, err := encryptPassword(user.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encrypt password"})
		return
	}
	user.Password = encryptedPassword

	// Store user data in Redis
	err = rdb.HSet(c.Request.Context(), "users", user.Username, user.UserID).Err()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}
	err = rdb.HSet(c.Request.Context(), "emails", user.Email, user.UserID).Err()
	if err != nil {
		// Rollback previous user data
		rdb.HDel(c.Request.Context(), "users", user.Username)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	// Store user details in Redis
	err = rdb.HSet(c.Request.Context(), fmt.Sprintf("user:%s", user.UserID), map[string]interface{}{
		"userId":   user.UserID,
		"username": user.Username,
		"email":    user.Email,
		"password": user.Password,
	}).Err()

	if err != nil {
		// Rollback previous user data
		rdb.HDel(c.Request.Context(), "users", user.Username)
		rdb.HDel(c.Request.Context(), "emails", user.Email)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	// User creation successful
	c.JSON(http.StatusCreated, gin.H{"message": "User created successfully!"})
}

func loginHandler(c *gin.Context) {
	// Parse request body into LoginRequest struct
	var loginReq struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&loginReq); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
		return
	}

	// Retrieve user data from Redis
	userID, err := getUserIDByUsername(loginReq.Username)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// If user ID is empty, try retrieving it using the email
	if userID == "" {
		userID, err = getUserIDByEmail(loginReq.Username)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
			return
		}
	}

	// Retrieve user data from Redis using the retrieved userID
	userData, err := rdb.HGetAll(c.Request.Context(), fmt.Sprintf("user:%s", userID)).Result()
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Check if the user exists
	if len(userData) == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Extract the stored password from the user's data
	storedPassword, ok := userData["password"]
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Compare the provided password with the stored password
	if !comparePasswords(loginReq.Password, storedPassword) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Authentication successful
	c.JSON(http.StatusOK, gin.H{"message": "Login successful!"})
}

func usernameExists(username string) (bool, error) {
	return rdb.HExists(context.Background(), "users", username).Result()
}

func emailExists(email string) (bool, error) {
	return rdb.HExists(context.Background(), "emails", email).Result()
}

func getUserIDByUsername(username string) (string, error) {
	return rdb.HGet(context.Background(), "users", username).Result()
}

func getUserIDByEmail(email string) (string, error) {
	return rdb.HGet(context.Background(), "emails", email).Result()
}

func encryptPassword(password string) (string, error) {
	key := []byte("0123456789ABCDEF0123456789ABCDEF")
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	encrypted := make([]byte, aes.BlockSize+len(password))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(encrypted[aes.BlockSize:], []byte(password))
	copy(encrypted[:aes.BlockSize], iv)

	return base64.URLEncoding.EncodeToString(encrypted), nil
}

func decryptPassword(encryptedPassword string) (string, error) {
	key := []byte("0123456789ABCDEF0123456789ABCDEF")
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	encrypted, err := base64.URLEncoding.DecodeString(encryptedPassword)
	if err != nil {
		return "", err
	}

	if len(encrypted) < aes.BlockSize {
		return "", fmt.Errorf("invalid encrypted password")
	}

	iv := encrypted[:aes.BlockSize]
	encrypted = encrypted[aes.BlockSize:]

	decrypted := make([]byte, len(encrypted))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(decrypted, encrypted)

	return string(decrypted), nil
}

func comparePasswords(password, storedPassword string) bool {
	decryptedPassword, err := decryptPassword(storedPassword)
	if err != nil {
		return false
	}

	return password == decryptedPassword
}

func profileHandler(c *gin.Context) {
	// Get the username or email from the request parameters
	usernameOrEmail := c.Param("usernameOrEmail")

	// Retrieve the user's ID using the provided username or email
	userID, err := getUserIDByUsername(usernameOrEmail)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Retrieve the user's data from Redis
	userData, err := rdb.HGetAll(c.Request.Context(), fmt.Sprintf("user:%s", userID)).Result()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve user data"})
		return
	}

	// Check if the user exists
	if len(userData) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Remove the password from the user's data before sending the response
	delete(userData, "password")

	// Return the user's profile data
	c.JSON(http.StatusOK, userData)
}

func logoutHandler(c *gin.Context) {
	// Get the user's ID from the authentication token or session
	//userID := getCurrentUserID(c)

	// Perform any necessary logout operations (e.g., clearing authentication token, session, etc.)

	// Return a success message
	c.JSON(http.StatusOK, gin.H{"message": "Logout successful!"})
}


