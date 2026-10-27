package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"passgen/internal/server"
	"passgen/internal/vault"
)

func main() {
	home, _ := os.UserHomeDir()
	addr := flag.String("addr", "127.0.0.1:8080", "address to listen on")
	data := flag.String("vault", filepath.Join(home, ".passgen", "vault.json"), "path to the encrypted vault file")
	flag.Parse()

	srv := &http.Server{
		Addr:              *addr,
		Handler:           server.New(vault.New(*data)),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("passgen listening on http://%s (vault: %s)", *addr, *data)
	log.Fatal(srv.ListenAndServe())
}
