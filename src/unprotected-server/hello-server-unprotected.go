package main

import (
    "os"
    "encoding/json"
    "log"
    "net/http"
    dotenv "github.com/joho/godotenv"
)

type SuccessResponse struct {
    Message string `json:"message"`
}

func helloHandler(response http.ResponseWriter, request *http.Request) {
    response.Header().Set("Content-Type", "application/json")
    response.WriteHeader(http.StatusOK)
    json.NewEncoder(response).Encode(SuccessResponse{Message: "Hello, World!"})
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
    http.HandleFunc("/", helloHandler)
    startServer()
}
