# Approov Backend Quickstart - Go (Standard Library Only)

This project provides a server-side example of Approov token verification for a protected backend API. It exposes a simple API that verifies Approov tokens before granting access to protected endpoints and demonstrates how the endpoints behave under the current Approov configuration:

- `/unprotected` - no Approov token required.
- `/token-check` - requires a valid Approov token.
- `/token-binding` - requires a valid Approov token bound to a header value.
- `/token-double-binding` - requires a valid Approov token bound to two header values.

In this example, Approov protection is provided by `approovMiddleware` in [`ApproovApplication.go`](ApproovApplication.go). The level of protection is configured per endpoint via the `protectedRoutes` configuration and route registration in `registerRoutes`.

## Approov Token Verification Flow

1. **Token Request:**
   The Approov SDK inside the mobile app securely communicates with the Approov Cloud Service to obtain a short-lived Approov Token (a signed JWT).
   Additionally, you can use the CLI token commands to validate tokens, generate new ones, and set the data hash.

2. **Token Attachment:**
   The app attaches this token to every API request using the `Approov-Token` HTTP header.

3. **Server Validation:**
   The server verifies the token using the shared Approov secret, checking its:
   - Signature authenticity (HS256)
   - Expiration (`exp` claim)

4. **Token Binding (Optional):**
   Token binding is configured by the app via the Approov SDK, which hashes a chosen binding value (for example the `Authorization` header) and embeds it into the Approov token.
   The protected API then computes the same hash from the incoming request and verifies that it matches the `pay` claim, preventing token reuse or replay attacks.

5. **Request Decision:**
   If all checks pass -> the request is trusted and processed `200 OK`.
   If validation fails -> the server responds with `401 Unauthorized`.

## Requirements

1. **Approov account** - sign up for an Approov trial account.
2. **Approov CLI initialized** - confirm `approov whoami` works.
3. **Install curl** - ensure the `curl` CLI is available.
4. **Go toolchain** - Go 1.22 or later.
5. **Create .env file** - copy `.env.example` so there is a place to store the secret key.
   ```bash
   cp .env.example .env
   ```

6. **Configure secret** - fetch the secret and add it to `.env` (`APPROOV_BASE64URL_SECRET`):
   ```bash
   approov secret -get base64url
   ```

7. **Register API domain** - point Approov at your backend API (default example.com):
   ```bash
   approov api -add example.com
   ```

## Run the Server

```bash
# from NewLanguage/
go run ApproovApplication.go
```

The server listens on `http://0.0.0.0:8080` by default. You can override this with:

```bash
export HTTP_PORT=8080
export SERVER_HOSTNAME=0.0.0.0
```

## Automated and Manual Testing

When the server is running (in a different terminal), validate the endpoints via the automated bash script or by running the manual checks below:

```bash
bash test.sh
```

This script:
- Verifies that the `approov` and `curl` commands are installed.
- Checks Approov status by calling `/approov-state` (enabled vs disabled).
- Runs endpoint tests against `/unprotected` (no token), `/token-check` (valid/invalid Approov tokens), `/token-binding` (token bound to `Authorization`), and `/token-double-binding` (token bound to `Authorization` + `Content-Digest`).
- Logs full request/response details to `.config/logs/<timestamp>.log`.

### Unprotected Endpoint (No Approov)

```bash
curl -iX GET http://localhost:8080/unprotected
```

### Approov Token Check

Generate a valid token:

```bash
approov token -genExample example.com
```

Use the token in the `Approov-Token` header:

```bash
curl -iX GET http://localhost:8080/token-check \
     -H "Approov-Token: valid_approov_token_here"
```

### Approov Token Binding Check

Generate a valid token bound to the `Authorization` header:

```bash
approov token -setDataHashInToken ExampleAuthToken== -genExample example.com
```

Call the endpoint with both headers:

```bash
curl -iX GET http://localhost:8080/token-binding \
     -H "Approov-Token: valid_approov_token_here" \
     -H "Authorization: ExampleAuthToken=="
```

### Approov Token Binding Check with Two Headers

Generate a valid token bound to `Authorization` and `Content-Digest`:

```bash
approov token -setDataHashInToken ExampleAuthToken==ContentDigest== -genExample example.com
```

Call the endpoint with all headers:

```bash
curl -iX GET http://localhost:8080/token-double-binding \
     -H "Approov-Token: valid_approov_token_here" \
     -H "Authorization: ExampleAuthToken==" \
     -H "Content-Digest: ContentDigest=="
```

## Enable or Disable Approov Protection

When the server is running on `localhost:8080`, you can toggle Approov protection with:

```bash
curl -X POST http://localhost:8080/approov/disable
curl -X POST http://localhost:8080/approov/enable
curl -X GET http://localhost:8080/approov-state
```

Token binding can be toggled separately:

```bash
curl -X POST http://localhost:8080/token-binding/disable
curl -X POST http://localhost:8080/token-binding/enable
```

## Mandatory Approov Logic Mapping (Code Links)

1. **JWT Approov Token validation (signature + expiry)** is implemented in `verifyApproovToken` (includes the `exp` check) in [`ApproovApplication.go`](ApproovApplication.go#L244-L295).
2. **Token binding (pay + hash)** is handled by `verifyApproovTokenBinding` (hash + compare) in [`ApproovApplication.go`](ApproovApplication.go#L297-L314).
3. **Middleware enforcement** is done by `approovMiddleware` in [`ApproovApplication.go`](ApproovApplication.go#L202-L242).
4. **Binding value selection (what gets hashed)** is in `bindingValueForRequest` (header selection + concatenation) in [`ApproovApplication.go`](ApproovApplication.go#L317-L343).
5. **Protected route requirements** are defined in `protectedRoutes` in [`ApproovApplication.go`](ApproovApplication.go#L40-L44).
6. **Protected routes are registered** in `registerRoutes` in [`ApproovApplication.go`](ApproovApplication.go#L111-L123).

## Copy-and-paste Approov Verification Code

Use these helpers to validate the Approov token signature, expiry, and token binding payload (`pay`) in any Go server:

```go
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

	computed := hashBase64URL(bindingValue)
	pay = strings.TrimSpace(pay)
	if computed == pay {
		return nil
	}

	// Compatibility fallback for tokens that still use standard base64.
	if hashBase64Std(bindingValue) == pay {
		return nil
	}

	return errors.New("invalid token binding")
}
```

Copy the helper functions from [`ApproovApplication.go`](ApproovApplication.go) as-is:
- `decodeBase64URL`
- `decodeJSONMap`
- `validateExpiration`
- `parseNumericClaim`
- `hmacSHA256`
- `hashBase64URL`
- `hashBase64Std`
- `hasText`

## Reporting Issues

**Environments where the quickstart was tested:**

```
Runtime: Go 1.22
Framework: None (net/http)
Build Tool: go
```

If you encounter any problems while following this guide, please open an issue and we will be happy to assist you.
