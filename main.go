package main

import (
	"log"
	"net/http"
	"os"

	"viuz_api/handlers"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
)

func main() {
	// Load environment variables
	err := godotenv.Load()
	if err != nil {
		log.Println("Error loading .env file")
	}

	// Initialize Router
	r := mux.NewRouter()

	// Auth Route
	r.HandleFunc("/api/auth/login", handlers.Login).Methods("POST")

	// Start Server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("Server running on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}
