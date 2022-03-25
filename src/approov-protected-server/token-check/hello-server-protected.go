package main

import (
    "os"
    "fmt"
    "encoding/json"
    "encoding/base64"
    "log"
    "net/http"
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
            errorResponse(response, http.StatusUnauthorized, "Approov: token is invalid.")
            return
        }

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
