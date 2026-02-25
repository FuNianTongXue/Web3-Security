package main

import (
	"flag"
	"fmt"
	"log"

	"scaudit/internal/webapp"
)

func main() {
	port := flag.Int("port", 8088, "listen port")
	flag.Parse()

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("SCaudit API: http://127.0.0.1%s", addr)
	if err := webapp.Run(addr); err != nil {
		log.Fatal(err)
	}
}
