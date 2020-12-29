package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/veehaitch/crtpin"
	"log"
	"net/http"
	"strconv"
	"strings"
)

var allowRebind *bool

type jsonResponse struct {
	Result *crtpin.Result `json:"result"`
	Error  *error         `json:"error"`
}

func serve(listenHost string, listenPort int) {
	r := mux.NewRouter()
	r.StrictSlash(true)
	r.Path("/").HandlerFunc(usage).Methods("GET")
	r.Path("/{host}").HandlerFunc(handle).Methods("GET")

	addr := fmt.Sprintf("[%s]:%d", listenHost, listenPort)
	go log.Fatal(http.ListenAndServe(addr, r))
}

func usage(w http.ResponseWriter, r *http.Request) {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("usage: https://%s/<host>[?port=<port>]\n", r.Host))
	b.WriteString(fmt.Sprintf("       https://%s/vincent-haupert.de\n", r.Host))
	b.WriteString(fmt.Sprintf("       https://%s/imap.gmail.com?port=993\n", r.Host))

	http.Error(w, b.String(), http.StatusOK)
}

func handle(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	host := vars["host"]
	port := 443
	if value := r.FormValue("port"); value != "" {
		parsed, err := strconv.ParseInt(value, 10, 16)
		if err == nil {
			port = int(parsed)
		}
	}

	res, err := crtpin.Crtpin(host, port, *allowRebind)
	jsonRes := jsonResponse{
		Result: res,
		Error:  &err,
	}

	w.Header().Set("Content-Type", "application/json")
	js, _ := json.Marshal(jsonRes)
	w.Write(js)
}

func main() {
	var listenHost = flag.String("host", "::1", "Listening host")
	var listenPort = flag.Int("port", 8888, "Listening port")
	allowRebind = flag.Bool("allow-rebind", false, "Also connect to a host which resolves to a private IPv4/IPv6 address")
	flag.Parse()

	fmt.Printf("Listening at %s:%d\n", *listenHost, *listenPort)
	fmt.Printf("DNS rebind allowed: %t\n", *allowRebind)
	if len(flag.Args()) > 0 {
		fmt.Println("Unknown command line arguments: ", flag.Args())
	}

	serve(*listenHost, *listenPort)
}
