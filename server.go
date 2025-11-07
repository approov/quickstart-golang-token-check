package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"

	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/joho/godotenv"
)

// ========== 1. Configuration ==========

type Config struct {
	Enabled      bool
	Base64Secret string
	TokenHeader  string
	Host         string
	Port         string
}

var config Config
var mu sync.RWMutex // for thread-safe config updates

func loadConfig() {
	_ = godotenv.Load() // ignore missing .env (optional)

	config = Config{
		Enabled:      os.Getenv("APPROOV_ENABLED") != "false",
		Base64Secret: os.Getenv("APPROOV_BASE64_SECRET"),
		TokenHeader:  os.Getenv("APPROOV_TOKEN_HEADER"),
		Host:         os.Getenv("SERVER_HOSTNAME"),
		Port:         os.Getenv("HTTP_PORT"),
	}

	if config.TokenHeader == "" {
		config.TokenHeader = "Approov-Token"
	}
	if config.Host == "" {
		config.Host = "localhost"
	}
	if config.Port == "" {
		config.Port = "8002"
	}

	if config.Base64Secret == "" {
		log.Fatal("[approov] missing APPROOV_BASE64_SECRET in environment")
	}
}

// ========== 2. Helpers ==========

func jsonResponse(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func sha256Base64(value string) string {
	hash := sha256.Sum256([]byte(value))
	return base64.StdEncoding.EncodeToString(hash[:])
}

// ========== 3. Approov Protection Middleware ==========

func approovProtected(handler http.HandlerFunc, boundHeaders []string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		mu.RLock()
		enabled := config.Enabled
		secret := config.Base64Secret
		headerName := http.CanonicalHeaderKey(config.TokenHeader)
		mu.RUnlock()

		if !enabled {
			log.Println("[approov] protection disabled")
			handler(w, r)
			return
		}

		tokenString := r.Header.Get(headerName)
		if tokenString == "" {
			jsonResponse(w, http.StatusUnauthorized, map[string]string{
				"error": fmt.Sprintf("[approov] missing %s header", headerName),
			})
			return
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method")
			}
			return base64.StdEncoding.DecodeString(secret)
		})

		if err != nil || !token.Valid {
			jsonResponse(w, http.StatusUnauthorized, map[string]string{
				"error": "[approov] invalid or expired token",
			})
			return
		}

		// Token binding (optional)
		if len(boundHeaders) > 0 {
			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				jsonResponse(w, http.StatusUnauthorized, map[string]string{"error": "invalid token claims"})
				return
			}
			pay, ok := claims["pay"].(string)
			if !ok {
				jsonResponse(w, http.StatusUnauthorized, map[string]string{"error": "missing 'pay' claim"})
				return
			}
			combined := ""
			for _, h := range boundHeaders {
				val := r.Header.Get(h)
				if val == "" {
					jsonResponse(w, http.StatusUnauthorized, map[string]string{
						"error": fmt.Sprintf("missing bound header '%s'", h),
					})
					return
				}
				combined += val
			}
			computed := sha256Base64(combined)
			if computed != pay {
				jsonResponse(w, http.StatusUnauthorized, map[string]string{
					"error": fmt.Sprintf("binding mismatch (expected %s, got %s)", computed, pay),
				})
				return
			}
		}

		handler(w, r)
	}
}

// ========== 4. Routes ==========

func unprotectedHandler(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, http.StatusOK, map[string]string{"message": "Unprotected endpoint reached"})
}

func tokenCheckHandler(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, http.StatusOK, map[string]string{"message": "Token valid"})
}

func tokenBinding1Handler(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, http.StatusOK, map[string]string{"message": "Token binding (one header) valid"})
}

func tokenBinding2Handler(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, http.StatusOK, map[string]string{
		"message": "Token binding (two headers) valid",
	})
}

func approovStateHandler(w http.ResponseWriter, r *http.Request) {
	state := "enabled"
	mu.RLock()
	if !config.Enabled {
		state = "disabled"
	}
	mu.RUnlock()
	jsonResponse(w, http.StatusOK, map[string]string{"state": state})
}

func approovEnableHandler(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	config.Enabled = true
	mu.Unlock()
	jsonResponse(w, http.StatusOK, map[string]string{"message": "Approov protection enabled"})
}

func approovDisableHandler(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	config.Enabled = false
	mu.Unlock()
	jsonResponse(w, http.StatusOK, map[string]string{"message": "Approov protection disabled"})
}

// ========== 5. Startup ==========

func main() {
	loadConfig()

	http.HandleFunc("/unprotected", unprotectedHandler)
	http.HandleFunc("/token-check", approovProtected(tokenCheckHandler, nil))
	http.HandleFunc("/token-binding-1", approovProtected(tokenBinding1Handler, []string{"Authorization"}))
	http.HandleFunc("/token-binding-2", approovProtected(tokenBinding2Handler, []string{"Authorization", "Content-Digest"}))
	http.HandleFunc("/approov-state", approovStateHandler)
	http.HandleFunc("/approov/enable", approovEnableHandler)
	http.HandleFunc("/approov/disable", approovDisableHandler)

	log.Printf("Server running at http://%s:%s\n", config.Host, config.Port)
	if err := http.ListenAndServe(config.Host+":"+config.Port, nil); err != nil {
		log.Fatal(err)
	}

}
