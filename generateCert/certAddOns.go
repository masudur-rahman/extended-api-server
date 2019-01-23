package generateCert

import (
	"crypto/rsa"
	"crypto/x509"
	"github.com/pkg/errors"
	"io/ioutil"
	"k8s.io/client-go/util/cert"
	"net"
)

func (store *CertStore) InitCA(prefix string) error {

	return store.NewCA(prefix)
}

func (store *CertStore) NewCA(prefix string) error {
	store.Prefix = prefix

	key, err := cert.NewPrivateKey()
	if err != nil {
		return errors.Wrap(err, "Failed to generate private key")
	}


	return store.createCAFromKey(key)
}

func (store *CertStore) createCAFromKey(key *rsa.PrivateKey) error {

	cfg := cert.Config{
		CommonName:	store.ca,
		AltNames:	cert.AltNames{
			DNSNames:	[]string{store.ca},
			IPs: 		[]net.IP{net.ParseIP("127.0.0.1")},
		},
	}
	crt, err := cert.NewSelfSignedCACert(cfg, key)
	if err != nil {
		return errors.Wrapf(err, "Failed to generate self-signed certificate")
	}

	err = store.WriteToFile(store.ca, crt, key)
	if err != nil {
		return err
	}

	store.caCert = crt
	store.caKey = key

	return nil
}

func (store *CertStore) WriteToFile(name string, crt *x509.Certificate, key *rsa.PrivateKey) error {
	if err := ioutil.WriteFile(store.Path+store.Prefix+"-"+name+".crt", cert.EncodeCertPEM(crt), 0777); err != nil {
		return errors.Wrapf(err, "Failed to write `%s`", store.Prefix+"-"+name+".crt",)
	}

	if err := ioutil.WriteFile(store.Path+store.Prefix+"-"+name+".key", cert.EncodePrivateKeyPEM(key), 0777); err != nil {
		return errors.Wrapf(err, "Failed to write `%s`", store.Prefix+"-"+name+".key",)

	}

	return nil
}

func (store *CertStore) NewServerCertPair(alternames cert.AltNames) (*x509.Certificate, *rsa.PrivateKey, error) {
	cfg := cert.Config{
		CommonName:	func() string {
			if len(alternames.DNSNames) > 0{
				return alternames.DNSNames[0]
			}
			if len(alternames.IPs) > 0 {
				return alternames.IPs[0].String()
			}
			return ""
		}(),
		AltNames:	alternames,
		Usages:		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	key, err := cert.NewPrivateKey()
	if err != nil {
		return nil, nil, errors.Wrap(err, "Failed to generate private key")
	}
	crt, err := cert.NewSignedCert(cfg, key, store.caCert, store.caKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Failed to generate signed certificate")
	}

	return crt, key, nil
}

func (store *CertStore) NewClientCertPair(alternames cert.AltNames) (*x509.Certificate, *rsa.PrivateKey, error) {
	cfg := cert.Config{
		CommonName:	func() string {
			if len(alternames.DNSNames) > 0{
				return alternames.DNSNames[0]
			}
			if len(alternames.IPs) > 0 {
				return alternames.IPs[0].String()
			}
			return ""
		}(),
		AltNames:	alternames,
		Usages:		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	key, err := cert.NewPrivateKey()
	if err != nil {
		return nil, nil, errors.Wrap(err, "Failed to generate private key")
	}
	crt, err := cert.NewSignedCert(cfg, key, store.caCert, store.caKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Failed to generate signed certificate")
	}

	return crt, key, nil
}
