package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type Credentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type User struct {
	ID       int    `json:"id"`
	Email    string `json:"email"`
	Password string `json:"-"`
	Name     string `json:"name"`
}

type Response struct {
	Status  string      `json:"status"`
	Message string      `json:"message,omitempty"`
	Token   string      `json:"token,omitempty"`
	User    interface{} `json:"user,omitempty"`
}

// Database connection
func connectDB() (*sql.DB, error) {
	dbURL := os.Getenv("DATABASE_URL")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		return nil, err
	}
	return db, nil
}

// Login Handler
func Login(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	db, err := connectDB()
	if err != nil {
		http.Error(w, "Database connection error", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	// Get user by email
	var user User
	query := "SELECT id, email, password, name FROM users WHERE email=$1"
	err = db.QueryRow(query, creds.Email).Scan(&user.ID, &user.Email, &user.Password, &user.Name)
	if err != nil {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	// Check password
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(creds.Password))
	if err != nil {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	// Generate JWT Token
	token, err := generateJWT(user)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// Response
	response := Response{
		Status: "success",
		Token:  token,
		User: map[string]interface{}{
			"id":    user.ID,
			"email": user.Email,
			"name":  user.Name,
		},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Generate JWT Token
func generateJWT(user User) (string, error) {
	secret := os.Getenv("JWT_SECRET")
	claims := jwt.MapClaims{
		"id":    user.ID,
		"email": user.Email,
		"exp":   time.Now().Add(time.Hour * 1).Unix(), // 1-hour expiry
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}
