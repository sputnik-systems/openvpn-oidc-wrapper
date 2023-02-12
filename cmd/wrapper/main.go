package main

import (
	"log"

	"github.com/sputnik-systems/openvpn-oidc-wrapper/internal/app"
)

func main() {
	log.SetFlags(log.Llongfile)

	if err := app.Execute(); err != nil {
		log.Fatalln(err)
	}
}
