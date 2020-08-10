package main

import (
	"fmt"
	"github.com/joho/godotenv"
	"github.com/nitrajka/al_ny_fe/api"
	"os"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		exit("could not load .env variables")
	}

	server, err := api.NewUserServer(
		"http://" +LoadEnvAddress("BACK_END_HOST", "BACK_END_PORT", "8000", "localhost"))
	if err != nil {
		exit(fmt.Sprintf("application terminated: %v", err))
	}

	err = server.Engine.Run(
		LoadEnvAddress("HOST", "PORT", "8080", "localhost"))
	if err != nil {
		exit("app terminated")
	}
}

func LoadEnvAddress(hostEnvName, portEnvName, defaultPort, defaultHost string) string {
	host := os.Getenv(hostEnvName)
	port := os.Getenv(portEnvName)

	if host == "" {
		host = defaultHost
	}

	if port == "" {
		port = defaultPort
	}

	return host + ":" + port
}

func exit(msg string) {
	fmt.Println(msg)
	os.Exit(1)
}
