package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const (
	defaultHTTPPort = "8080"
	defaultHost     = "0.0.0.0"

	envApproovSecret = "APPROOV_BASE64URL_SECRET"
	envHTTPPort      = "HTTP_PORT"
	envHost          = "SERVER_HOSTNAME"

	approovHeader = "Approov-Token"
	authHeader    = "Authorization"
	digestHeader  = "Content-Digest"

	approovSecretPlaceholder = "approov_base64url_secret_here"
)

type protectedRoute struct {
	Path           string
	BindingHeaders []string
}

var protectedRoutes = []protectedRoute{
	{Path: "/token-check"},
	{Path: "/token-binding", BindingHeaders: []string{authHeader}},
	{Path: "/token-double-binding", BindingHeaders: []string{authHeader, digestHeader}},
}

var protectedRouteIndex = func() map[string]protectedRoute {
	index := make(map[string]protectedRoute, len(protectedRoutes))
	for _, route := range protectedRoutes {
		index[route.Path] = route
	}
	return index
}()

var approovEnabled atomic.Bool
var tokenBindingEnabled atomic.Bool
var approovSecret []byte

func init() {
	approovEnabled.Store(true)
	tokenBindingEnabled.Store(true)
}

type errorResponse struct {
	Error string `json:"error"`
}

type infoResponse struct {
	ApproovEnabled      bool   `json:"approovEnabled"`
	TokenBindingEnabled bool   `json:"tokenBindingEnabled"`
	Details             string `json:"details,omitempty"`
	AuthorizationHeader bool   `json:"authorizationHeaderPresent,omitempty"`
	ContentDigestHeader bool   `json:"contentDigestHeaderPresent,omitempty"`
}

type loggingResponseWriter struct {
	http.ResponseWriter
	status          int
	summary         string
	requiredHeaders []string
}

func main() {
	if err := loadEnvFile(".env"); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			log.Println(".env file not found; relying on environment variables")
		} else {
			log.Fatalf("Failed to load .env: %v", err)
		}
	}

	secret, err := loadApproovSecret()
	if err != nil {
		log.Fatalf("Unable to load Approov secret: %v", err)
	}
	approovSecret = secret

	host := envOrDefault(envHost, defaultHost)
	port := envOrDefault(envHTTPPort, defaultHTTPPort)

	mux := http.NewServeMux()
	registerRoutes(mux)

	server := &http.Server{
		Addr:              net.JoinHostPort(host, port),
		Handler:           loggingMiddleware(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Printf("Approov token check API listening on http://%s", server.Addr)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("Server error: %v", err)
	}
}

func registerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/", requireMethod(http.MethodGet, homeHandler))
	mux.HandleFunc("/approov-state", requireMethod(http.MethodGet, approovStateHandler))
	mux.HandleFunc("/approov/enable", requireMethod(http.MethodPost, enableApproovHandler))
	mux.HandleFunc("/approov/disable", requireMethod(http.MethodPost, disableApproovHandler))
	mux.HandleFunc("/token-binding/enable", requireMethod(http.MethodPost, enableTokenBindingHandler))
	mux.HandleFunc("/token-binding/disable", requireMethod(http.MethodPost, disableTokenBindingHandler))
	mux.HandleFunc("/unprotected", requireMethod(http.MethodGet, unprotectedHandler))

	mux.Handle("/token-check", approovMiddleware(http.HandlerFunc(requireMethod(http.MethodGet, tokenCheckHandler))))
	mux.Handle("/token-binding", approovMiddleware(http.HandlerFunc(requireMethod(http.MethodGet, tokenBindingHandler))))
	mux.Handle("/token-double-binding", approovMiddleware(http.HandlerFunc(requireMethod(http.MethodGet, tokenDoubleBindingHandler))))
}

func requireMethod(method string, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			w.Header().Set("Allow", method)
			writeError(w, http.StatusMethodNotAllowed, fmt.Errorf("method %s not allowed", r.Method))
			return
		}
		handler(w, r)
	}
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	payload := statePayload()
	payload.Details = fmt.Sprintf("Approov demo API is running on port %s.", envOrDefault(envHTTPPort, defaultHTTPPort))
	writeJSON(w, http.StatusOK, payload)
}

func approovStateHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, statePayload())
}

func enableApproovHandler(w http.ResponseWriter, r *http.Request) {
	approovEnabled.Store(true)
	tokenBindingEnabled.Store(true)
	writeJSON(w, http.StatusOK, statePayload())
}

func disableApproovHandler(w http.ResponseWriter, r *http.Request) {
	approovEnabled.Store(false)
	tokenBindingEnabled.Store(false)
	writeJSON(w, http.StatusOK, statePayload())
}

func enableTokenBindingHandler(w http.ResponseWriter, r *http.Request) {
	tokenBindingEnabled.Store(true)
	writeJSON(w, http.StatusOK, statePayload())
}

func disableTokenBindingHandler(w http.ResponseWriter, r *http.Request) {
	tokenBindingEnabled.Store(false)
	writeJSON(w, http.StatusOK, statePayload())
}

func unprotectedHandler(w http.ResponseWriter, r *http.Request) {
	payload := statePayload()
	payload.Details = "Unprotected endpoint '/unprotected'; no Approov checks performed."
	writeJSON(w, http.StatusOK, payload)
}

func tokenCheckHandler(w http.ResponseWriter, r *http.Request) {
	payload := statePayload()
	payload.Details = "Protected endpoint '/token-check'; Approov token verified."
	writeJSON(w, http.StatusOK, payload)
}

func tokenBindingHandler(w http.ResponseWriter, r *http.Request) {
	payload := statePayload()
	payload.Details = "Protected endpoint '/token-binding'; Approov token binding enforced."
	payload.AuthorizationHeader = hasText(strings.TrimSpace(r.Header.Get(authHeader)))
	writeJSON(w, http.StatusOK, payload)
}

func tokenDoubleBindingHandler(w http.ResponseWriter, r *http.Request) {
	payload := statePayload()
	payload.Details = "Protected endpoint '/token-double-binding'; dual token binding enforced."
	payload.AuthorizationHeader = hasText(strings.TrimSpace(r.Header.Get(authHeader)))
	payload.ContentDigestHeader = hasText(strings.TrimSpace(r.Header.Get(digestHeader)))
	writeJSON(w, http.StatusOK, payload)
}

func statePayload() infoResponse {
	return infoResponse{
		ApproovEnabled:      approovEnabled.Load(),
		TokenBindingEnabled: tokenBindingEnabled.Load(),
	}
}

func (lrw *loggingResponseWriter) WriteHeader(status int) {
	lrw.status = status
	lrw.ResponseWriter.WriteHeader(status)
}

func (lrw *loggingResponseWriter) Write(data []byte) (int, error) {
	if lrw.status == 0 {
		lrw.status = http.StatusOK
	}
	count, err := lrw.ResponseWriter.Write(data)
	return count, err
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lrw := &loggingResponseWriter{ResponseWriter: w}
		next.ServeHTTP(lrw, r)

		status := lrw.status
		if status == 0 {
			status = http.StatusOK
		}
		if status != http.StatusOK && status != http.StatusUnauthorized {
			return
		}

		summary := lrw.summary
		if summary == "" {
			if status == http.StatusUnauthorized {
				summary = "unauthorized"
			} else {
				summary = "ok"
			}
		}

		requiredHeaders := lrw.requiredHeaders
		if requiredHeaders == nil {
			requiredHeaders = []string{}
		}

		log.Printf(
			"http.request.completed summary=%q method=%q path=%q status=%d ip=%q port=%d approovEnabled=%t tokenBindingEnabled=%t required_headers=%s",
			summary,
			r.Method,
			r.URL.Path,
			status,
			requestClientIP(r),
			requestServerPort(r),
			approovEnabled.Load(),
			tokenBindingEnabled.Load(),
			formatHeaderList(requiredHeaders),
		)
	})
}

func setLogSummary(w http.ResponseWriter, summary string) {
	if summary == "" {
		return
	}
	if lrw, ok := w.(*loggingResponseWriter); ok {
		lrw.summary = summary
	}
}

func setLogRequiredHeaders(w http.ResponseWriter, headers []string) {
	if lrw, ok := w.(*loggingResponseWriter); ok {
		lrw.requiredHeaders = append([]string(nil), headers...)
	}
}

func requiredHeadersForRoute(route protectedRoute) []string {
	headers := []string{approovHeader}
	if tokenBindingEnabled.Load() && len(route.BindingHeaders) > 0 {
		headers = append(headers, route.BindingHeaders...)
	}
	return headers
}

func requestClientIP(r *http.Request) string {
	remote := strings.TrimSpace(r.RemoteAddr)
	if remote == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(remote)
	if err == nil && host != "" {
		return host
	}
	return remote
}

func requestServerPort(r *http.Request) int {
	hostPort := strings.TrimSpace(r.Host)
	if hostPort != "" {
		_, port, err := net.SplitHostPort(hostPort)
		if err == nil {
			if value, err := strconv.Atoi(port); err == nil {
				return value
			}
		}
	}
	if value, err := strconv.Atoi(envOrDefault(envHTTPPort, defaultHTTPPort)); err == nil {
		return value
	}
	return 0
}

func formatHeaderList(headers []string) string {
	payload, err := json.Marshal(headers)
	if err != nil {
		return "[]"
	}
	return string(payload)
}

func approovMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route, ok := protectedRouteIndex[r.URL.Path]
		if !ok {
			next.ServeHTTP(w, r)
			return
		}

		if !approovEnabled.Load() {
			setLogSummary(w, "approov_disabled")
			next.ServeHTTP(w, r)
			return
		}

		setLogRequiredHeaders(w, requiredHeadersForRoute(route))

		rawToken, err := extractSingleHeaderValue(r.Header, approovHeader)
		if err != nil {
			setLogSummary(w, "approov_failed:missing_approov_token")
			writeUnauthorized(w, err)
			return
		}

		claims, err := verifyApproovToken(rawToken, approovSecret, time.Now().UTC())
		if err != nil {
			setLogSummary(w, "approov_failed:token_verification_failed")
			writeUnauthorized(w, err)
			return
		}

		if len(route.BindingHeaders) > 0 && tokenBindingEnabled.Load() {
			bindingValue, err := bindingValueForRequest(route, r)
			if err != nil {
				setLogSummary(w, "approov_failed:missing_binding_header")
				writeUnauthorized(w, err)
				return
			}
			if err := verifyApproovTokenBinding(claims, bindingValue); err != nil {
				setLogSummary(w, "approov_failed:binding_mismatch")
				writeUnauthorized(w, err)
				return
			}
		}

		setLogSummary(w, "approov_ok")
		next.ServeHTTP(w, r)
	})
}

func verifyApproovToken(rawToken string, secret []byte, now time.Time) (map[string]any, error) {
	token := strings.TrimSpace(rawToken)
	if token == "" {
		return nil, errors.New("token is missing in the request headers")
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("token format must have three segments")
	}

	headerBytes, err := decodeBase64URL(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode token header: %w", err)
	}

	header, err := decodeJSONMap(headerBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token header: %w", err)
	}

	alg, ok := header["alg"].(string)
	if !ok || alg != "HS256" {
		return nil, errors.New("token signing method mismatch")
	}

	signature, err := decodeBase64URL(parts[2])
	if err != nil {
		return nil, fmt.Errorf("failed to decode token signature: %w", err)
	}

	expected := hmacSHA256(secret, parts[0]+"."+parts[1])
	if !hmac.Equal(signature, expected) {
		return nil, errors.New("token signature mismatch")
	}

	payloadBytes, err := decodeBase64URL(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode token payload: %w", err)
	}

	claims, err := decodeJSONMap(payloadBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token payload: %w", err)
	}

	if err := validateExpiration(claims, now); err != nil {
		return nil, err
	}

	return claims, nil
}

func verifyApproovTokenBinding(claims map[string]any, bindingValue string) error {
	pay, ok := claims["pay"].(string)
	if !ok || !hasText(pay) {
		return errors.New("token binding missing pay claim")
	}

	computed := hashBase64Std(bindingValue)
	expected := strings.TrimSpace(pay)
	if hmac.Equal([]byte(computed), []byte(expected)) {
		return nil
	}

	return errors.New("invalid token binding")
}

func bindingValueForRequest(route protectedRoute, r *http.Request) (string, error) {
	if len(route.BindingHeaders) == 0 {
		return "", errors.New("no binding headers configured")
	}

	var builder strings.Builder
	for _, headerName := range route.BindingHeaders {
		value, err := extractSingleHeaderValue(r.Header, headerName)
		if err != nil {
			return "", err
		}
		builder.WriteString(value)
	}

	return builder.String(), nil
}

func extractSingleHeaderValue(headers http.Header, name string) (string, error) {
	values := headers.Values(name)
	if len(values) != 1 {
		return "", fmt.Errorf("header %s is missing, empty, or repeated", name)
	}
	value := strings.TrimSpace(values[0])
	if value == "" {
		return "", fmt.Errorf("header %s is missing, empty, or repeated", name)
	}
	return value, nil
}

func validateExpiration(claims map[string]any, now time.Time) error {
	expValue, ok := claims["exp"]
	if !ok {
		return errors.New("token missing exp claim")
	}

	exp, err := parseNumericClaim(expValue)
	if err != nil {
		return errors.New("token exp claim is invalid")
	}

	expiration := time.Unix(exp, 0)
	if !expiration.After(now) {
		return errors.New("token is expired")
	}

	return nil
}

func parseNumericClaim(value any) (int64, error) {
	n, ok := value.(json.Number)
	if !ok {
		return 0, errors.New("exp must be a JSON number")
	}
	return n.Int64()
}

func hmacSHA256(secret []byte, message string) []byte {
	h := hmac.New(sha256.New, secret)
	_, _ = h.Write([]byte(message))
	return h.Sum(nil)
}

func hashBase64Std(value string) string {
	hash := sha256.Sum256([]byte(value))
	return base64.StdEncoding.EncodeToString(hash[:])
}

func decodeBase64URL(value string) ([]byte, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil, errors.New("empty base64url value")
	}
	if padding := len(trimmed) % 4; padding != 0 {
		trimmed += strings.Repeat("=", 4-padding)
	}
	return base64.URLEncoding.DecodeString(trimmed)
}

func decodeJSONMap(data []byte) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var payload map[string]any
	if err := decoder.Decode(&payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func hasText(value string) bool {
	return strings.TrimSpace(value) != ""
}

func envOrDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func loadApproovSecret() ([]byte, error) {
	secret := strings.TrimSpace(os.Getenv(envApproovSecret))
	if secret == "" {
		log.Println("Required secret is not set")
		return nil, fmt.Errorf("%s environment variable is not set", envApproovSecret)
	}
	if secret == approovSecretPlaceholder {
		log.Println("Required secret is not set")
		return nil, fmt.Errorf("%s environment variable is not set", envApproovSecret)
	}
	decoded, err := decodeBase64URL(secret)
	if err != nil {
		log.Println("Required secret is invalid")
		return nil, fmt.Errorf("%s must be base64url encoded: %w", envApproovSecret, err)
	}
	return decoded, nil
}

func loadEnvFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		value = strings.Trim(value, "\"'")
		if key == "" {
			continue
		}
		if _, exists := os.LookupEnv(key); !exists {
			_ = os.Setenv(key, value)
		}
	}
	return scanner.Err()
}

func writeUnauthorized(w http.ResponseWriter, err error) {
	writeError(w, http.StatusUnauthorized, err)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, errorResponse{Error: err.Error()})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(true)
	if err := encoder.Encode(payload); err != nil {
		log.Printf("Failed to write response: %v", err)
	}
}
