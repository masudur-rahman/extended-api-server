package main

import (
	"github.com/gorilla/mux"
	"github.com/masudur-rahman/extended-api-server/generateCert"
	"github.com/masudur-rahman/extended-api-server/kubernetes-apiserver/appsServer"
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
		log.Fatal(err)
	}


	err = store.InitCA("kubernetes")
	if err != nil {
		log.Fatalln(err)
	}


	serverCert, serverKey, err := store.NewServerCertPair(cert.AltNames{
		IPs:	[]net.IP{net.ParseIP("127.0.0.2")},
	})
	if err != nil {
		log.Fatalln(err)
	}
	err = store.WriteToFile("tls", serverCert, serverKey)
	if err != nil {
		log.Fatalln(err)
	}


	clientCert, ClientKey, err := store.NewClientCertPair(cert.AltNames{
		DNSNames:	[]string{"jane"},
	})
	if err != nil {
		log.Fatalln(err)
	}
	err = store.WriteToFile("client", clientCert, ClientKey)
	if err != nil {
		log.Fatalln(err)
	}



	router := mux.NewRouter()
	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Println("You just reached kubernetes server root")
	})
	appsServer.CreateInitialWorkerProfile()
	router.HandleFunc("/appscode/workers", appsServer.ShowAllWorkers)
	router.HandleFunc("/appscode/workers/", appsServer.ShowAllWorkers)
	router.HandleFunc("/appscode/workers/{username}", appsServer.ShowSingleWorker)
	router.HandleFunc("/appscode/workers/{username}/", appsServer.ShowSingleWorker)

	cfg := server.Config{
		Address:		"127.0.0.2:8443",
		CACertificates:	[]string{
			store.Path+"kubernetes-ca.crt",
		},
		CertFile: 		store.Path+"kubernetes-tls.crt",
		KeyFile: 		store.Path+"kubernetes-tls.key",
	}

	srvr := &http.Server{
		Addr: 			cfg.Address,
		ReadTimeout:	5*time.Second,
		WriteTimeout: 	10*time.Second,
		Handler:		router,
	}
	srvr.TLSConfig = server.GetTlsConfig(cfg)

	log.Println("Kubernetes Server is now serving at 127.0.0.2:8443")

	err = srvr.ListenAndServeTLS(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		log.Fatalln(err)
	}

}
