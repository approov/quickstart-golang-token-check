// files/approov.go
package files

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"

	jwt "github.com/golang-jwt/jwt/v4"
)

type Verifier struct {
	SecretB64      string
	TokenHeader    string   // e.g. "Approov-Token"
	BindingHeaders []string // optional
	// later: fields/hooks for message-sign + ipk
}

func NewVerifier(secretB64, tokenHeader string, bindingHeaders []string) *Verifier {
	if tokenHeader == "" {
		tokenHeader = "Approov-Token"
	}
	return &Verifier{
		SecretB64:      secretB64,
		TokenHeader:    tokenHeader,
		BindingHeaders: bindingHeaders,
	}
}

// helper: decode secret in the same way as the Lua quickstart (base64url, usually unpadded)
func (v *Verifier) decodeSecret() ([]byte, error) {
	// 1) Try URL-safe *without* padding (what the Lua quickstart uses)
	if b, err := base64.RawURLEncoding.DecodeString(v.SecretB64); err == nil {
		return b, nil
	}

	// 2) Try URL-safe *with* padding
	if b, err := base64.URLEncoding.DecodeString(v.SecretB64); err == nil {
		return b, nil
	}

	// 3) Fall back to standard base64 (for people using openssl-generated secrets, etc.)
	b, err := base64.StdEncoding.DecodeString(v.SecretB64)
	if err != nil {
		return nil, fmt.Errorf("bad secret: %w", err)
	}
	return b, nil
}

func (v *Verifier) Verify(r *http.Request) error {
	// 1) JWT verify (HS256)
	tokenStr := r.Header.Get(v.TokenHeader)
	if tokenStr == "" {
		return fmt.Errorf("missing %s header", v.TokenHeader)
	}

	secret, err := v.decodeSecret()
	if err != nil {
		return err
	}

	tok, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return secret, nil
	})
	if err != nil || !tok.Valid {
		return fmt.Errorf("invalid or expired token")
	}

	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return fmt.Errorf("invalid token claims")
	}

	// 2) Optional token binding
	if len(v.BindingHeaders) > 0 {
		pay, _ := claims["pay"].(string)

		var combined string
		for _, h := range v.BindingHeaders {
			val := r.Header.Get(h)
			if val == "" {
				return fmt.Errorf("missing bound header %q", h)
			}
			combined += val
		}
		sum := sha256.Sum256([]byte(combined))
		if base64.StdEncoding.EncodeToString(sum[:]) != pay {
			return fmt.Errorf("token binding mismatch")
		}
	}

	// 3) Optional message signature (ipk)
	if ipk, ok := claims["ipk"].(string); ok && ipk != "" {
		if err := VerifyMessageSignature(r, ipk); err != nil {
			return fmt.Errorf("http message signature verification failed: %w", err)
		}
	}

	return nil
}
