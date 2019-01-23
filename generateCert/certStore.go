package generateCert

import (
	"crypto/rsa"
	"crypto/x509"
	"github.com/pkg/errors"
	"os"
)

var rootDir string
var gitUser string = "masudur-rahman"
var localUser string = "masud"

func init() {
	rootDir = "/home/"+localUser+"/go/src/github.com/"+gitUser+"/extended-api-server/"
}


type CertStore struct {
	Path	string
	Prefix	string
	ca		string
	caKey	*rsa.PrivateKey
	caCert	*x509.Certificate
}

func InitCertStore(path string) (*CertStore, error) {
	_, err := os.Stat(rootDir+path)

	if os.IsNotExist(err) {
		err := os.Mkdir(rootDir+path, 0777)

		if err != nil {
			return nil, errors.Wrapf(err, "Failed to create directory: `%s`\n", rootDir+path)
		}
	}

	return &CertStore{
		Path:	rootDir+path+"/",
		ca:		"ca",
	}, nil

}
