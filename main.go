package main

import (
	"fmt"
	"os"

	"github.com/nitrajka/al_ny_fe/pkg/api"
)

func main() {
	clientId := os.Getenv("GOOGLE_OAUTH_CLIENT_ID")
	clientSecret := os.Getenv("GOOGLE_OAUTH_CLIENT_SECRET")
	selfAddr := ":" + os.Getenv("PORT")
	backEndAddr := os.Getenv("BACK_END_ADDR")

	server, err := api.NewUserServer(backEndAddr, clientId, clientSecret, selfAddr)
	if err != nil {
		exit(fmt.Sprintf("application terminated: %v", err))
	}

	err = server.Engine.Run(selfAddr)
	if err != nil {
		exit("app terminated")
	}
}

func exit(msg string) {
	fmt.Println(msg)
	os.Exit(1)
}
