package main

import (
	"log"
	"net/http"

	"github.com/SimpleFNAFer/dplm/backend/internal/api"
	"github.com/SimpleFNAFer/dplm/backend/internal/mlclient"
	"github.com/SimpleFNAFer/dplm/backend/internal/store"
)

func main() {
	s := store.New()
	ml := mlclient.New()
	router := api.NewRouter(s, ml)

	addr := ":8080"
	log.Printf("CSRF scanner backend listening on %s", addr)
	if err := http.ListenAndServe(addr, router); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
