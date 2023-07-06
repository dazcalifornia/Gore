package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"time"

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

type SessionData struct {
	Username string `json:"username"`
	Verified bool   `json:"verified"`
}

type Session struct {
	UserID string
	Token  string
}

var sessions map[string]Session

func main() {
	// Establish Redis connection
	rdb = redis.NewClient(&redis.Options{
		Addr:     "localhost:6379", // Replace with your Redis server address
		Password: "",               // Add password if required
		DB:       0,                // Use the default database
	})

	// Initialize the sessions map
	sessions = make(map[string]Session)

	// Create a new Gin router
	router := gin.Default()

	// Define the routes
	router.POST("/users", createUserHandler)
	router.POST("/login", loginHandler)
	router.GET("/profile/:usernameOrEmail", profileHandler)
	router.POST("/logout", logoutHandler)
	router.POST("/profile/update", updateProfileHandler)

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
	err = rdb.HSet(c.Request.Context(), fmt.Sprintf("user:%s", user.UserID),
	map[string]interface{}{
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

	// Create a new profile database if it doesn't exist
	profileKey := fmt.Sprintf("profile:%s", user.UserID)
	_, err = rdb.Get(c.Request.Context(), profileKey).Result()
	if err == redis.Nil {
		// Profile database doesn't exist, create a new one
		err = rdb.HSet(c.Request.Context(), profileKey, map[string]interface{}{
			"userId":        user.UserID,
			"profilePicture": "",
			"profileName":   "",
			"bio":           "",
		}).Err()
		if err != nil {
			// Rollback previous user and profile data
			rdb.HDel(c.Request.Context(), "users", user.Username)
			rdb.HDel(c.Request.Context(), "emails", user.Email)
			rdb.Del(c.Request.Context(), fmt.Sprintf("user:%s", user.UserID))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create profile database"})
			return
		}
	}

	// User creation successful
	c.JSON(http.StatusCreated, gin.H{"message": "User created successfully!"})
}

func generateToken() string {
	token := make([]byte, 32)
	_, err := rand.Read(token)
	if err != nil {
		log.Fatal(err)
	}
	return base64.URLEncoding.EncodeToString(token)
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
	
	// Compare the provided password with the stored password
	if !comparePasswords(loginReq.Password, storedPassword) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Create a new session for the user
	token := generateToken()
	sessionData := map[string]interface{}{
		"username": loginReq.Username,
		"verified": "1",
	}
	sessionDataJSON, err := json.Marshal(sessionData)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create session"})
		return
	}

	// Store the session in Redis using the SET command
	expiration := time.Hour * 24 * 30 // 30 days

// Store the session in Redis
err = rdb.HSet(c.Request.Context(), "sessions", token, sessionDataJSON).Err()
if err != nil {
    c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create session"})
    return
}


	// Return the session token to the client
	c.JSON(http.StatusOK, gin.H{"token": token})
}

func logoutHandler(c *gin.Context) {
	// Get the token from the request header
	token := c.GetHeader("Authorization")

	// Check if the token is valid
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid token"})
		return
	}

	// Delete the session from Redis
	err := rdb.Del(c.Request.Context(), "session:"+token).Err()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete session"})
		return
	}

	// Logout successful
	c.JSON(http.StatusOK, gin.H{"message": "Logout successful"})
}
