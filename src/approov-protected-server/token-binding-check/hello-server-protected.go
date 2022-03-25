package main

import (
    "os"
    "fmt"
    "encoding/json"
    "encoding/base64"
    "log"
    "net/http"
    "crypto/sha256"
    jwt "github.com/dgrijalva/jwt-go"
    dotenv "github.com/joho/godotenv"
)

type SuccessResponse struct {
    Message string `json:"message"`
}

type ErrorResponse struct {}

func errorResponse(response http.ResponseWriter, statusCode int, message string) {
    response.Header().Set("Content-Type", "application/json")
    response.WriteHeader(statusCode)
    json.NewEncoder(response).Encode(ErrorResponse{})
}

func helloHandler(response http.ResponseWriter, request *http.Request) {
    response.Header().Set("Content-Type", "application/json")
    response.WriteHeader(http.StatusOK)
    json.NewEncoder(response).Encode(SuccessResponse{Message: "Hello, World!"})
}

func verifyApproovToken(request *http.Request, base64Secret string)  (*jwt.Token, error) {
    approovToken := request.Header["Approov-Token"]

    if approovToken == nil {
        return nil, fmt.Errorf("token is missing in the request headers.")
    }

    token, err := jwt.Parse(approovToken[0], func(token *jwt.Token) (interface{}, error) {

        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("token signing method mismatch.")
        }

        secret, err := base64.StdEncoding.DecodeString(base64Secret)

        if err != nil {
            return nil, fmt.Errorf(err.Error())
        }

        return secret, nil
    })

    return token, err
}

func verifyApproovTokenBinding(token *jwt.Token, request *http.Request) (jwt.Claims, error) {
    claims := token.Claims
    token_binding_payload, has_pay_key := claims.(jwt.MapClaims)["pay"]

    if ! has_pay_key {
        return claims, fmt.Errorf("the `pay` claim is missing in the token payload.")
    }

    // We use the Authorization token here, but feel free to use another header.
    // However, no matter the header you choose, you also need to bind it to the
    // Approov token in the mobile app.
    token_binding_header := request.Header["Authorization"]

    // If the request as more then 1 Authorization header you want to return an
    // error.
    // NEVER choose one of the headers, otherwise you are opening yourself to
    // potential attacks.
    if len(token_binding_header) != 1 {
        return claims, fmt.Errorf("the header to perform the verification for the token binding is missing, empty or has more than one entry.")
    }

    // We need to hash and base64 encode the token binding header to match how
    // it was done when it was included on the Approov token.
    token_binding_header_hashed := sha256.Sum256([]byte(token_binding_header[0]))
    token_binding_header_encoded := base64.StdEncoding.EncodeToString(token_binding_header_hashed[:])

    if token_binding_payload != token_binding_header_encoded {
        return claims, fmt.Errorf("invalid token binding.")
    }

    return claims, nil
}

func makeApproovCheckerHandler(handler func(http.ResponseWriter, *http.Request), base64Secret string) http.Handler {
    return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {

        token, err := verifyApproovToken(request, base64Secret)

        if err != nil {
            // You may want to remove logging, replace or change how its logging
            log.Println("Approov: " + err.Error())
            errorResponse(response, http.StatusUnauthorized, err.Error())
            return
        }

        if ! token.Valid {
            // You may want to remove logging, replace or change how its logging
            log.Println("Approov: " + err.Error())
            errorResponse(response, http.StatusUnauthorized, "Token is invalid.")
            return
        }

        claims, err := verifyApproovTokenBinding(token, request)

        if err != nil {
            // You may want to remove logging, replace or change how its logging
            log.Println("Approov: " + err.Error())
            errorResponse(response, http.StatusUnauthorized, err.Error())
            return
        }

        // Use the returned claims to perform any additional checks.
        _ = claims

        handler(response, request)
    })
}

func startServer() {
    httpPort, exists := os.LookupEnv("HTTP_PORT")

    if !exists {
        httpPort = "8002"
    }

    log.Println("Server listening on http://localhost:" + httpPort)

    err := http.ListenAndServe(":" + httpPort, nil)

    if err != nil {
        log.Fatal("Server Error: " + err.Error())
    }
}

func init() {
    // loads values from .env file into the host system environment
    err := dotenv.Load();

    if err != nil {
        log.Fatal("Rename the .env.example file to .env and try again.")
    }
}

func main() {
    base64Secret, exists := os.LookupEnv("APPROOV_BASE64_SECRET")

    if !exists {
        log.Fatal("The .env file is missing the env var: APPROOV_BASE64_SECRET")
    }

    http.Handle("/", makeApproovCheckerHandler(helloHandler, base64Secret))
    startServer()
}
