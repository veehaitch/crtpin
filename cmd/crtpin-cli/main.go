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
	var allowRebind = flag.Bool("allow-rebind", false, "Also connect to a host which resolves to a private IPv4/IPv6 address")
	flag.Parse()

	if *host == "" {
		log.Fatal("host parameter not given")
	}

	res, err := crtpin.Crtpin(*host, *port, *allowRebind)
	if err != nil {
		panic(err)
	}

	data, err := json.MarshalIndent(*res, "", "  ")
	if err != nil {
		panic(err)
	}

	fmt.Println(string(data))
}
