package server

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"
)

type Config struct {
	Address			string
	CACertificates	[]string
	CertFile		string
	KeyFile			string
}

func GetTlsConfig(cfg Config) *tls.Config{
	if cfg.CertFile == "" || cfg.KeyFile == "" {
		log.Fatalln("Missing certificates")
	}

	tlsConfig := &tls.Config{
		PreferServerCipherSuites:	true,
		MinVersion:					tls.VersionTLS12,
		SessionTicketsDisabled:		true,
		CipherSuites:				[]uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, // Go 1.8 only
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,   // Go 1.8 only
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		ClientAuth:	tls.VerifyClientCertIfGiven,
		NextProtos:	[]string{"h2", "http/1.1"},
	}

	caCertPool := x509.NewCertPool()
	for _, caFile := range cfg.CACertificates {
		caCert, err := ioutil.ReadFile(caFile)
		if err != nil {
			log.Fatalln(err)
		}
		caCertPool.AppendCertsFromPEM(caCert)
	}
	tlsConfig.ClientCAs = caCertPool
	tlsConfig.BuildNameToCertificate()

	return tlsConfig
}