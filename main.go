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
	// ตรวจสอบว่าโปรแกรมกำลังรันบน Railway หรือไม่
	if os.Getenv("DATABASE_URL") == "" {
		// โหลด .env ในเครื่องเท่านั้น
		err := godotenv.Load()
		if err != nil {
			log.Println("Error loading .env file")
		}
	}

	// Initialize Router
	r := mux.NewRouter()

	// Apply CORS Middleware
	r.Use(corsMiddleware)

	// Auth Route
	r.HandleFunc("/api/auth/login", handlers.Login).Methods("POST")
	r.HandleFunc("/api/auth/change-password", handlers.ChangePassword).Methods("POST")
	r.HandleFunc("/api/auth/register", handlers.Register).Methods("POST")

	// Start Server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("Server running on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// ตั้งค่า Headers สำหรับ CORS
		w.Header().Set("Access-Control-Allow-Origin", "http://localhost:4200") // ระบุ Origin
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		// Handle Preflight Request (OPTIONS)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		// เรียก handler ถ้าไม่ใช่ OPTIONS
		next.ServeHTTP(w, r)
	})
}
