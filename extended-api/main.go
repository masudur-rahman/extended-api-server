package main

import (
	"crypto/tls"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/masudur-rahman/extended-api-server/generateCert"
	"github.com/masudur-rahman/extended-api-server/server"
	"k8s.io/client-go/util/cert"
	"log"
	"net"
	"net/http"
	"time"
)

func main() {
	store, err := generateCert.InitCertStore("certificates")
	
	if err != nil {
		log.Fatalln(err)
	}
	
	err = store.InitCA("apiserver")

	if err != nil {
		log.Fatalln(err)
	}

	serverCert, serverKey, err := store.NewServerCertPair(cert.AltNames{
		IPs:	[]net.IP{net.ParseIP("127.0.0.1")},
	})
	if err != nil {
		log.Fatalln(err)
	}
	err = store.WriteToFile("tls", serverCert, serverKey)
	if err != nil {
		log.Fatalln(err)
	}

	clientCert, clientKey, err := store.NewClientCertPair(cert.AltNames{
		DNSNames:	[]string{"masud"},
	})
	if err != nil {
		log.Fatalln(err)
	}
	err = store.WriteToFile("client", clientCert, clientKey)

	//----------------------Request Header Certificate------------------------------

	rhStore, err := generateCert.InitCertStore("certificates")
	if err != nil {
		log.Fatalln(err)
	}
	err = rhStore.InitCA("request-header")
	if err != nil {
		log.Fatalln(err)
	}
	rhClientCert, rhClientKey, err := rhStore.NewClientCertPair(cert.AltNames{
		DNSNames:	[]string{"apiserver"},
	})
	if err != nil {
		log.Fatalln(err)
	}
	err = rhStore.WriteToFile("apiserver", rhClientCert, rhClientKey)
	if err != nil {
		log.Fatalln(err)
	}
	rhCert, err := tls.LoadX509KeyPair( rhStore.Path+rhStore.Prefix+"-"+"apiserver"+".crt", rhStore.Path+rhStore.Prefix+"-"+"apiserver"+".key",)
	if err != nil {
		log.Fatalln(err)
	}

	// ------------------------------------------------------------------
	log.Println(rhCert)



	router := mux.NewRouter()
	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Println("You just reached server root")
	})
	router.HandleFunc("/extended/{info}", Welcome)

	cfg := server.Config{
		Address: 		"127.0.0.1:8443",
		CACertificates:	[]string{
			store.Path+"apiserver-ca.crt",
		},
		CertFile:		store.Path+"apiserver-tls.crt",
		KeyFile:		store.Path+"apiserver-tls.key",
	}

	srvr := &http.Server{
		Addr:			cfg.Address,
		ReadTimeout:	5*time.Second,
		WriteTimeout:	10*time.Second,
		Handler:		router,
	}
	srvr.TLSConfig = server.GetTlsConfig(cfg)
	err = srvr.ListenAndServeTLS(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		log.Fatalln(err)
	}
}

func Welcome(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	w.WriteHeader(http.StatusOK)
	log.Println("Extended API:",vars["info"])
	_, _ = fmt.Fprintf(w, "Extended Api: %v\n", vars["info"])
}
