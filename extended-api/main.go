package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/masudur-rahman/extended-api-server/generateCert"
	"github.com/masudur-rahman/extended-api-server/server"
	"io"
	"k8s.io/client-go/util/cert"
	"log"
	"net"
	"net/http"
	"time"
)

var easCACertPool *x509.CertPool
var rhCert tls.Certificate


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
	err = rhStore.InitCA("requestheader")
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
	
	rhCert, err = tls.LoadX509KeyPair( rhStore.Path+rhStore.Prefix+"-"+"apiserver"+".crt", rhStore.Path+rhStore.Prefix+"-"+"apiserver"+".key",)
	if err != nil {
		log.Fatalln(err)
	}

	// ------------------------------------------------------------------
	easCACertPool = x509.NewCertPool()
	easStore, err := generateCert.InitCertStore("certificates")
	if err != nil {
		log.Fatalln(err)
	}

	err = easStore.InitCA("kubernetes")
	if err != nil {
		log.Fatalln(err)
	}
	easCACertPool.AppendCertsFromPEM(cert.EncodeCertPEM(easStore.CaCert))

	// ------------------------------------------------------------------
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
		ReadTimeout:	5 * time.Second,
		WriteTimeout:	10 * time.Second,
		Handler:		router,
	}
	srvr.TLSConfig = server.GetTlsConfig(cfg)


	router.HandleFunc("/appscode/workers", ExtendServer)
	router.HandleFunc("/appscode/workers/", ExtendServer)
	router.HandleFunc("/appscode/workers/{username}", ExtendServer)
	router.HandleFunc("/appscode/workers/{username}/", ExtendServer)

	log.Println("API Server is now serving at 127.0.0.1:8443")
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

func ExtendServer(w http.ResponseWriter, r *http.Request, ) {
	tr := &http.Transport{
		MaxIdleConnsPerHost:	10,
		TLSClientConfig:		&tls.Config{
			Certificates: 		[]tls.Certificate{rhCert},
			RootCAs: 			easCACertPool,
		},
	}
	client := http.Client{
		Transport: 	tr,
		Timeout: 	time.Duration(30 * time.Second),
	}

	u := *r.URL
	u.Scheme = "https"
	u.Host = "127.0.0.2:8443"
	log.Println("Forwarding to", u.String())

	req, _ := http.NewRequest(r.Method, u.String(), nil)
	if len(r.TLS.PeerCertificates) > 0 {
		req.Header.Set("X-Remote-User", r.TLS.PeerCertificates[0].Subject.CommonName)
	}

	//log.Println("Request: ", req)

	resp, err := client.Do(req)

	//log.Println("Response received:", resp, err)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprintf(w, "error: %v\n", err.Error())
		return
	}
	defer resp.Body.Close()

	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, resp.Body)
}
