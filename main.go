package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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

	// Generate a new UUID for the user
	user.UserID = uuid.New().String()

	// Encrypt the user's password
	user.Password = encryptPassword(user.Password)

	// Store user data in Redis
	err := rdb.HSet(c.Request.Context(), fmt.Sprintf("user:%s", user.UserID), map[string]interface{}{
		"userId":   user.UserID,
		"username": user.Username,
		"email":    user.Email,
		"password": user.Password,
	}).Err()

	if err != nil {
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
	val := rdb.HGet(c.Request.Context(), fmt.Sprintf("user:%s", loginReq.Username), "password").Val()
	if val == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Check if the provided password matches the stored password
	storedPassword := val
	if storedPassword != encryptPassword(loginReq.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Authentication successful
	c.JSON(http.StatusOK, gin.H{"message": "Login successful!"})
}

func encryptPassword(password string) string {
	// Use SHA-256 for password encryption
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:])
}
