package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/veehaitch/crtpin"
	"log"
)

func main() {
	var host = flag.String("host", "", "Host for which to fetch the certificate")
	var port = flag.Int("port", 443, "Host port of the TLS server")
	var filterPrivate = flag.Bool("filter-private", false, "Whether to filter requests which resolve to private IPv4/IPv6 ranges")
	flag.Parse()

	if *host == "" {
		log.Fatal("host parameter not given")
	}

	res, err := crtpin.Crtpin(*host, *port, *filterPrivate)
	if err != nil {
		panic(err)
	}

	data, err := json.MarshalIndent(*res, "", "  ")
	if err != nil {
		panic(err)
	}

	fmt.Println(string(data))
}
