FROM golang:1.18-bullseye
WORKDIR /app
RUN go mod tidy
COPY . .
EXPOSE 8111
CMD ["go", "run", "server.go"]
