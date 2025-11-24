package files

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strings"
)

// SigParams holds the parsed Signature-Input parameters for sig1.
type SigParams struct {
	Components []string // e.g. ["@method", "@target-uri", "approov-token", "content-digest"]
	InnerRaw   string   // e.g. ("@method" "approov-token");alg="ecdsa-p256-sha256";created=...
}

// parseSignatureInputHeader parses a header like:
//
//	Signature-Input: sig1=("@method" "approov-token");alg="ecdsa-p256-sha256";created=...;expires=...
func parseSignatureInputHeader(h string) (*SigParams, error) {
	if h == "" {
		return nil, fmt.Errorf("missing Signature-Input header")
	}

	// We assume a single entry: sig1=...
	eq := strings.Index(h, "=")
	if eq <= 0 {
		return nil, fmt.Errorf("invalid Signature-Input (no '='): %q", h)
	}

	value := strings.TrimSpace(h[eq+1:])
	if value == "" {
		return nil, fmt.Errorf("empty Signature-Input value")
	}

	if !strings.HasPrefix(value, "(") {
		return nil, fmt.Errorf("invalid Signature-Input (no '('): %q", h)
	}

	closeIdx := strings.Index(value, ")")
	if closeIdx < 0 {
		return nil, fmt.Errorf("invalid Signature-Input (no ')'): %q", h)
	}

	innerList := value[1:closeIdx] // everything between '(' and ')'

	// innerList looks like: "@method" "@target-uri" "approov-token" "content-digest"
	var comps []string
	for _, part := range strings.Split(innerList, "\" \"") {
		part = strings.Trim(part, `" `)
		if part == "" {
			continue
		}
		comps = append(comps, part)
	}

	if len(comps) == 0 {
		return nil, fmt.Errorf("no components found in Signature-Input: %q", h)
	}

	return &SigParams{
		Components: comps,
		InnerRaw:   value, // keep the raw `("...")...` part for @signature-params
	}, nil
}

func buildCanonicalMessage(r *http.Request, sp *SigParams) ([]byte, error) {
	var lines []string

	for _, comp := range sp.Components {
		switch comp {
		case "@method":
			lines = append(lines, fmt.Sprintf("\"@method\": %s", strings.ToUpper(r.Method)))
		case "@target-uri":
			scheme := "http"
			if r.TLS != nil {
				scheme = "https"
			}
			target := fmt.Sprintf("%s://%s%s", scheme, r.Host, r.URL.RequestURI())
			lines = append(lines, fmt.Sprintf("\"@target-uri\": %s", target))
		case "approov-token":
			token := r.Header.Get("Approov-Token")
			if token == "" {
				token = r.Header.Get("approov-token")
			}
			if token == "" {
				return nil, fmt.Errorf("missing Approov-Token header")
			}
			lines = append(lines, fmt.Sprintf("\"approov-token\": %s", token))
		case "content-digest":
			cd := r.Header.Get("Content-Digest")
			if cd == "" {
				cd = r.Header.Get("content-digest")
			}
			if cd == "" {
				return nil, fmt.Errorf("missing Content-Digest header")
			}
			lines = append(lines, fmt.Sprintf("\"content-digest\": %s", cd))
		default:
			return nil, fmt.Errorf("unsupported signature component %q", comp)
		}
	}

	lines = append(lines, fmt.Sprintf("\"@signature-params\": %s", sp.InnerRaw))
	canonical := strings.Join(lines, "\n")

	h := sha256.Sum256([]byte(canonical))
	log.Printf("CANONICAL MESSAGE:\n%s", canonical)
	log.Printf("SHA256(b64) = %s", base64.StdEncoding.EncodeToString(h[:]))

	return []byte(canonical), nil
}

// extractSignatureBytes parses a header like:
//
//	Signature: sig1=:BASE64SIG:
//
// and returns the decoded bytes.
func extractSignatureBytes(h string) ([]byte, error) {
	if h == "" {
		return nil, fmt.Errorf("missing Signature header")
	}

	// find the first "=:"
	start := strings.Index(h, "=:")
	if start < 0 {
		return nil, fmt.Errorf("Signature header not in expected format: %q", h)
	}
	start += len("=:")

	end := strings.Index(h[start:], ":")
	if end < 0 {
		return nil, fmt.Errorf("Signature header missing closing ':'")
	}

	b64 := strings.TrimSpace(h[start : start+end])
	if b64 == "" {
		return nil, fmt.Errorf("empty signature value in Signature header")
	}

	sig, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("base64 decode signature: %w", err)
	}

	return sig, nil
}

// parsePublicKeyFromIPK decodes the ipk claim (base64 DER EC P-256 public key).
func parsePublicKeyFromIPK(ipkB64 string) (*ecdsa.PublicKey, error) {
	if ipkB64 == "" {
		return nil, errors.New("empty ipk")
	}

	der, err := base64.StdEncoding.DecodeString(ipkB64)
	if err != nil {
		return nil, fmt.Errorf("base64 decode ipk: %w", err)
	}

	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse ipk DER: %w", err)
	}

	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("ipk is not an ECDSA P-256 public key")
	}

	return ecdsaPub, nil
}

// verifyECDSARaw matches the Lua `ecdsa_use_raw = true` signing:
// sig is 64 bytes: r||s (each 32 bytes), SHA-256 over the message.
func verifyECDSARaw(pub *ecdsa.PublicKey, msg []byte, sig []byte) error {
	if len(sig) != 64 {
		return fmt.Errorf("unexpected ECDSA signature length %d (want 64)", len(sig))
	}

	h := sha256.Sum256(msg)

	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])

	if !ecdsa.Verify(pub, h[:], r, s) {
		return errors.New("ECDSA signature verification failed")
	}

	return nil
}

// VerifyMessageSignature is called after the Approov token has been checked,
// passing the ipk claim (base64 DER public key).
func VerifyMessageSignature(r *http.Request, ipk string) error {
	sp, err := parseSignatureInputHeader(r.Header.Get("Signature-Input"))
	if err != nil {
		return fmt.Errorf("parse Signature-Input: %w", err)
	}

	canonical, err := buildCanonicalMessage(r, sp)
	if err != nil {
		return fmt.Errorf("build canonical message: %w", err)
	}

	sig, err := extractSignatureBytes(r.Header.Get("Signature"))
	if err != nil {
		return fmt.Errorf("extract Signature: %w", err)
	}

	pub, err := parsePublicKeyFromIPK(ipk)
	if err != nil {
		return fmt.Errorf("parse ipk: %w", err)
	}

	if err := verifyECDSARaw(pub, canonical, sig); err != nil {
		return err
	}

	return nil
}
