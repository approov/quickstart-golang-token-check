#!/usr/bin/env bash
set -e  # exit on error
echo "Setting Approov CLI"
sleep 2

approov api -list
echo "Checcking Authentication..."

go run server.go
echo "Server running..."
sleep 2

