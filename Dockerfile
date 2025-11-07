FROM golang:1.18-bullseye
WORKDIR /app
RUN go mod tidy
COPY . .
EXPOSE 8002
CMD ["go", "run", "server.go"]
