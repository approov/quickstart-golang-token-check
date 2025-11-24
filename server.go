package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

	"quickstart-golang-token-check/files"

	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/joho/godotenv"

	"github.com/ucarion/sfv"
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
		config.Port = "8111"
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
		headerName := config.TokenHeader // keep the raw name here
		mu.RUnlock()

		if !enabled {
			log.Println("[approov] protection disabled")
			handler(w, r)
			return
		}

		// Create a per-request verifier (or cache these per path if you like)
		verifier := files.NewVerifier(secret, headerName, boundHeaders)

		if err := verifier.Verify(r); err != nil {
			jsonResponse(w, http.StatusUnauthorized, map[string]string{
				"error": "[approov] " + err.Error(),
			})
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

// ipkMessageSignHandler signs the canonical message with the EC private key,
// returning a base64-encoded raw ECDSA (r||s) signature – similar to the Lua
// /ipk_message_sign_test endpoint.
func ipkMessageSignHandler(w http.ResponseWriter, r *http.Request) {
	pkB64 := r.Header.Get("private-key")
	msgB64 := r.Header.Get("msg")

	if pkB64 == "" || msgB64 == "" {
		http.Error(w, "Failed: missing private-key or msg header", http.StatusBadRequest)
		return
	}

	// Decode private key (b64 DER, EC P-256)
	pkDER, err := base64.StdEncoding.DecodeString(pkB64)
	if err != nil {
		http.Error(w, "Failed: bad private-key base64", http.StatusBadRequest)
		return
	}

	priv, err := x509.ParseECPrivateKey(pkDER)
	if err != nil {
		http.Error(w, "Failed: could not parse EC private key", http.StatusBadRequest)
		return
	}

	// Decode message (base64 of canonical string)
	msg, err := base64.StdEncoding.DecodeString(msgB64)
	if err != nil {
		http.Error(w, "Failed: bad msg base64", http.StatusBadRequest)
		return
	}

	// Hash and sign with ECDSA P-256 + SHA-256
	h := sha256.Sum256(msg)
	rInt, sInt, err := ecdsa.Sign(rand.Reader, priv, h[:])
	if err != nil {
		http.Error(w, "Failed: could not sign message", http.StatusInternalServerError)
		return
	}

	// Encode as raw r||s (same format your verifier expects)
	rb := rInt.Bytes()
	sb := sInt.Bytes()
	// simple concat; verifier will split in half – for production you'd
	// normally left-pad to fixed size, but keeping tests consistent is enough.
	// sigRaw := append(rb, sb...)

	if len(rb) > 32 || len(sb) > 32 {
		http.Error(w, "Failed: ECDSA coordinates too large", http.StatusInternalServerError)
		return
	}

	raw := make([]byte, 64)
	// pad r on the left
	copy(raw[32-len(rb):32], rb)
	// pad s on the left
	copy(raw[64-len(sb):64], sb)

	sigB64 := base64.StdEncoding.EncodeToString(raw)

	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, sigB64)
}

func SFVTestHandler(w http.ResponseWriter, r *http.Request) {
	sfvHeader := r.Header.Get("sfv")
	sfvType := r.Header.Get("sfvt") // ITEM, LIST, or DICTIONARY

	normalized, err := normalizeSFVInput(sfvHeader)
	if err != nil {
		http.Error(w, "SFV parse error: "+err.Error(), http.StatusBadRequest)
		return
	}

	var (
		parsed any
	)

	switch sfvType {
	case "ITEM":
		trimmed := strings.TrimSpace(normalized)
		if strings.HasPrefix(trimmed, "(") {
			var list sfv.List
			err = sfv.Unmarshal(normalized, &list)
			if err == nil {
				if len(list) != 1 {
					err = fmt.Errorf("expected single inner list, got %d members", len(list))
				} else if list[0].IsItem {
					err = fmt.Errorf("expected inner list value")
				} else {
					parsed = list[0].InnerList
				}
			}
		} else {
			var item sfv.Item
			err = sfv.Unmarshal(normalized, &item)
			parsed = item
		}

	case "LIST":
		var list sfv.List
		err = sfv.Unmarshal(normalized, &list)
		parsed = list

	case "DICTIONARY":
		var dict sfv.Dictionary
		err = sfv.Unmarshal(normalized, &dict)
		parsed = dict

	default:
		http.Error(w, "Invalid sfvt header (must be ITEM, LIST, or DICTIONARY)", http.StatusBadRequest)
		return
	}

	if err != nil {
		http.Error(w, "SFV parse error: "+err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(parsed)
}

func normalizeSFVInput(raw string) (string, error) {
	if raw == "" {
		return raw, nil
	}

	var b strings.Builder
	b.Grow(len(raw))

	inString := false
	escapeNext := false
	inBinary := false

	for i := 0; i < len(raw); {
		if !inString && !inBinary && raw[i] == '%' && i+1 < len(raw) && raw[i+1] == '"' {
			decoded, end, err := decodeDisplayString(raw, i+2)
			if err != nil {
				return "", err
			}
			b.WriteByte('"')
			b.WriteString(escapeSFVString(decoded))
			b.WriteByte('"')
			i = end + 1 // skip closing quote
			continue
		}

		if !inString && !inBinary && raw[i] == '@' {
			start := i + 1
			sign := ""
			if start < len(raw) && raw[start] == '-' {
				sign = "-"
				start++
			}
			j := start
			for j < len(raw) && raw[j] >= '0' && raw[j] <= '9' {
				j++
			}
			if j > start {
				b.WriteString(sign)
				b.WriteString(raw[start:j])
				i = j
				continue
			}
		}

		ch := raw[i]
		b.WriteByte(ch)

		if inString {
			if escapeNext {
				escapeNext = false
			} else if ch == '\\' {
				escapeNext = true
			} else if ch == '"' {
				inString = false
			}
		} else if inBinary {
			if ch == ':' {
				inBinary = false
			}
		} else {
			if ch == '"' {
				inString = true
				escapeNext = false
			} else if ch == ':' {
				inBinary = true
			}
		}
		i++
	}

	return b.String(), nil
}

func decodeDisplayString(raw string, start int) (string, int, error) {
	var b strings.Builder

	for i := start; i < len(raw); i++ {
		ch := raw[i]
		if ch == '"' {
			return b.String(), i, nil
		}
		if ch == '\\' {
			i++
			if i >= len(raw) {
				return "", 0, fmt.Errorf("unterminated escape in display string")
			}
			b.WriteByte(raw[i])
			continue
		}
		b.WriteByte(ch)
	}

	return "", 0, fmt.Errorf("unterminated display string")
}

func escapeSFVString(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\', '"':
			b.WriteByte('\\')
			b.WriteByte(s[i])
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// ========== 5. Startup ==========

func main() {
	loadConfig()

	verifier := files.NewVerifier(config.Base64Secret, config.TokenHeader, nil)

	http.HandleFunc("/unprotected", unprotectedHandler)

	http.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		// Runs:
		// 1) JWT verification
		// 2) Optional token binding (if you pass BindingHeaders in NewVerifier)
		// 3) Message-sign check if the JWT has an "ipk" claim
		if err := verifier.Verify(r); err != nil {
			jsonResponse(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
			return
		}
		// If we get here, everything verified OK
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Good Token"))
	})
	http.HandleFunc("/token-check", approovProtected(tokenCheckHandler, nil))
	http.HandleFunc("/token-binding-1", approovProtected(tokenBinding1Handler, []string{"Authorization"}))
	http.HandleFunc("/token-binding-2", approovProtected(tokenBinding2Handler, []string{"Authorization", "Content-Digest"}))
	http.HandleFunc("/sfv_test", SFVTestHandler)
	http.HandleFunc("/ipk_message_sign_test", ipkMessageSignHandler)
	http.HandleFunc("/approov-state", approovStateHandler)
	http.HandleFunc("/approov/enable", approovEnableHandler)
	http.HandleFunc("/approov/disable", approovDisableHandler)

	log.Printf("Server running at http://%s:%s\n", config.Host, config.Port)
	if err := http.ListenAndServe(config.Host+":"+config.Port, nil); err != nil {
		log.Fatal(err)
	}

}
