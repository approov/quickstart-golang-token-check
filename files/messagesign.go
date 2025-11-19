// files/messagesign.go
package files

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"strings"
)

// SigParams is what we need from Signature-Input:
// - which components are covered (e.g. "@method", "@target-uri", "approov-token")
// - the canonical inner-list string used for "@signature-params"
type SigParams struct {
	Components []string // ["@method", "@target-uri", "approov-token", "content-digest", ...]
	InnerRaw   string   // e.g. ("@method" "@target-uri" "approov-token");alg="ecdsa-p256-sha256";...
}

// VerifyMessageSignature verifies the HTTP message signature using the ipk (b64 DER).
// This is the Go equivalent of Lua: messagesign.checkMessageSignature(public_key_b64, ...).
func VerifyMessageSignature(r *http.Request, ipkB64 string) error {
	// 1) Decode ipk (b64 DER) and parse as ECDSA public key (P-256)
	pubKey, err := parseIPK(ipkB64)
	if err != nil {
		return fmt.Errorf("parse ipk: %w", err)
	}

	sigInput := r.Header.Get("Signature-Input")
	sigHeader := r.Header.Get("Signature")
	if sigInput == "" || sigHeader == "" {
		return fmt.Errorf("missing Signature or Signature-Input headers")
	}

	label := "install"

	sp, err := parseSignatureInput(sigInput, label)
	if err != nil {
		return fmt.Errorf("parse Signature-Input: %w", err)
	}

	sigRaw, err := parseSignatureHeader(sigHeader, label)
	if err != nil {
		return fmt.Errorf("parse Signature header: %w", err)
	}

	canonical, err := buildCanonicalMessage(r, sp)
	if err != nil {
		return fmt.Errorf("build canonical message: %w", err)
	}

	h := sha256.Sum256(canonical)
	fmt.Println("CANONICAL MESSAGE:\n" + string(canonical))
	fmt.Println("SHA256(b64) =", base64.StdEncoding.EncodeToString(h[:]))

	if !verifyECDSARaw(pubKey, canonical, sigRaw) {
		return fmt.Errorf("ECDSA signature verification failed")
	}

	return nil
}

// parseIPK decodes a base64 DER PKIX public key into *ecdsa.PublicKey.
// Inspired by loadPublicKey in the http-signatures repo, but works with DER instead of PEM.
func parseIPK(ipkB64 string) (*ecdsa.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(ipkB64)
	if err != nil {
		return nil, fmt.Errorf("decode ipk base64: %w", err)
	}

	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("ParsePKIXPublicKey: %w", err)
	}

	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("ipk is not ECDSA")
	}
	return ec, nil
}

// verifyECDSARaw verifies a raw r||s ECDSA signature over the sha256 of msg.
// Based on the ECDSA logic from the previous repo, but without ASN.1.
func verifyECDSARaw(pub *ecdsa.PublicKey, msg []byte, sig []byte) bool {
	if len(sig) != 64 {
		return false
	}

	h := sha256.Sum256(msg)

	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])

	return ecdsa.Verify(pub, h[:], r, s)
}

// parseSignatureInput parses a Signature-Input header like:
//
//	install=("@method" "@target-uri" "approov-token");alg="ecdsa-p256-sha256";created=...;expires=...
//
// and returns the components + canonical inner-list string.
func parseSignatureInput(headerValue, label string) (*SigParams, error) {
	// Signature-Input is a structured *dictionary*.
	prefix := label + "="
	idx := strings.Index(headerValue, prefix)
	if idx < 0 {
		return nil, fmt.Errorf("label %q not found in Signature-Input", label)
	}

	inner := strings.TrimSpace(headerValue[idx+len(prefix):])
	if inner == "" {
		return nil, fmt.Errorf("empty inner-list for %q", label)
	}

	// inner is now: ("@method" "approov-token");alg="..."
	// Grab the bit between '(' and ')' to get the component tokens.
	start := strings.Index(inner, "(")
	end := strings.Index(inner, ")")
	if start < 0 || end <= start {
		return nil, fmt.Errorf("malformed inner-list in Signature-Input")
	}

	inside := inner[start+1 : end] // e.g. `"@method" "approov-token"`

	// Split on whitespace and strip quotes to get the component names.
	fields := strings.Fields(inside)
	comps := make([]string, 0, len(fields))
	for _, f := range fields {
		f = strings.TrimSpace(f)
		f = strings.Trim(f, "\"")
		if f != "" {
			comps = append(comps, f)
		}
	}
	if len(comps) == 0 {
		return nil, fmt.Errorf("no components found in Signature-Input")
	}

	return &SigParams{
		Components: comps,
		InnerRaw:   inner, // use the header substring verbatim for @signature-params
	}, nil
}

// parseSignatureHeader extracts the raw signature bytes from
//
//	Signature: install=:<b64-sig>:
//
// for the given label.
func parseSignatureHeader(headerValue, label string) ([]byte, error) {
	// Example expected: 'install=:BASE64:'
	// You can search for `label + =:` prefix and the next ':'.
	prefix := label + "=:"
	idx := strings.Index(headerValue, prefix)
	if idx < 0 {
		return nil, fmt.Errorf("label %q not found in Signature header", label)
	}
	rest := headerValue[idx+len(prefix):]
	end := strings.Index(rest, ":")
	if end < 0 {
		return nil, fmt.Errorf("malformed Signature header")
	}
	b64 := rest[:end]

	sig, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("decode signature base64: %w", err)
	}
	return sig, nil
}

// buildCanonicalMessage rebuilds the exact signature base string.
// This MUST match what your Lua `http-message-sign` + bash tests generate.
// For now this is a skeleton; fill it in using your test script examples.
func buildCanonicalMessage(r *http.Request, sp *SigParams) ([]byte, error) {
	var sb strings.Builder

	// Build each covered component line in order
	for _, comp := range sp.Components {
		switch comp {
		case "@method":
			sb.WriteString("\"@method\": " + r.Method + "\n")

		case "@target-uri":
			// Must match the bash script: e.g. http://0.0.0.0:8111/token?param1=value1&param2=value2
			target := "http://" + r.Host + r.URL.RequestURI()
			sb.WriteString("\"@target-uri\": " + target + "\n")

		case "approov-token":
			token := r.Header.Get("Approov-Token")
			if token == "" {
				token = r.Header.Get("approov-token") // in case of lowercase
			}
			sb.WriteString("\"approov-token\": " + token + "\n")

		case "content-digest":
			cd := r.Header.Get("Content-Digest")
			sb.WriteString("\"content-digest\": " + cd + "\n")

		default:
			return nil, fmt.Errorf("unsupported signature component %q", comp)
		}
	}

	// IMPORTANT: final line with newline, to match the bash script / Lua version
	sb.WriteString("\"@signature-params\": " + sp.InnerRaw + "\n")

	return []byte(sb.String()), nil
}
