docker-compose up -d --remove-orphans
sleep 2
echo ""
echo "Approov protected server is running."

echo "Checking authentication service is up..."
approov api -list

sleep 2

go run server.go &

echo ""
echo "Running tests..."
./tests.sh

sleep 2
echo ""
echo "Tests completed. Stopping the server..."
docker-compose down