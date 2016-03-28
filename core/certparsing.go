package core

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

type Certificate struct {
	Certificate *x509.Certificate
	PrivateKey  crypto.PrivateKey
}

func (c *Certificate) LoadCertificateFromFile(certPath string) error {
	certData, err := ioutil.ReadFile(certPath)
	if err != nil {
		return err
	}

	x509Cert, err := parseCertificate(certData)
	if err != nil {
		return err
	}

	c.Certificate = x509Cert
	return nil
}

func (c *Certificate) LoadCertificateFromURL(url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("Unable to fetch certificate from %s: %s", url, err)
	}
	defer resp.Body.Close()

	certData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("Unable to fetch certificate from %s: %s", url, err)
	}

	x509Cert, err := parseCertificate(certData)
	if err != nil {
		return fmt.Errorf("Unable to parse certificate from %s: %s", url, err)
	}

	c.Certificate = x509Cert
	return nil
}

func (c *Certificate) LoadPrivateKeyFromFile(keyPath string) error {
	keyData, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return err
	}

	privateKey, err := parsePrivateKey(keyData)
	if err != nil {
		return err
	}

	c.PrivateKey = privateKey
	return nil
}

func (c *Certificate) EnsureCertificateAndKeyMatch() error {
	switch publicKey := c.Certificate.PublicKey.(type) {
	case *rsa.PublicKey:
		rsaPrivateKey, ok := c.PrivateKey.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf(
				"Public key is %T but private key is %T", publicKey, rsaPrivateKey)
		}
		if publicKey.N.Cmp(rsaPrivateKey.N) != 0 {
			return fmt.Errorf("Private RSA key doesn't match public RSA key")
		}
	case *ecdsa.PublicKey:
		ecdsaPrivateKey, ok := c.PrivateKey.(*ecdsa.PrivateKey)
		if !ok {
			return fmt.Errorf(
				"Public key is %T but private key is %T", publicKey, ecdsaPrivateKey)
		}
		if publicKey.X.Cmp(ecdsaPrivateKey.X) != 0 || publicKey.Y.Cmp(ecdsaPrivateKey.Y) != 0 {
			return fmt.Errorf("Private ECDSA key doesn't match public ECDSA key")
		}
	default:
		return fmt.Errorf("Unknown key algorithm")
	}

	return nil
}

func CertificateWithKeyFromFiles(certPath, keyPath string) (*Certificate, error) {
	rv := &Certificate{}

	if err := rv.LoadCertificateFromFile(certPath); err != nil {
		return nil, err
	}
	if err := rv.LoadPrivateKeyFromFile(keyPath); err != nil {
		return nil, err
	}
	if err := rv.EnsureCertificateAndKeyMatch(); err != nil {
		return nil, err
	}

	return rv, nil
}

func CertificateFromURL(url string) (*Certificate, error) {
	rv := &Certificate{}
	if err := rv.LoadCertificateFromURL(url); err != nil {
		return nil, err
	}

	return rv, nil
}

func parseCertificate(data []byte) (*x509.Certificate, error) {
	certs, err := parseCertificates(data)
	if err != nil {
		return nil, err
	}
	if len(certs) < 1 {
		return nil, fmt.Errorf("No certificates were found")
	}
	if len(certs) > 1 {
		warning("More than one certificate found, considering only the first")
	}
	return certs[0], nil
}

func parseCertificates(data []byte) ([]*x509.Certificate, error) {
	derCertificates := [][]byte{}

	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			continue
		}

		derCertificates = append(derCertificates, block.Bytes)
	}

	if len(derCertificates) > 0 {
		data = bytes.Join(derCertificates, []byte{})
	}

	rv, err := x509.ParseCertificates(data)
	if err != nil {
		return nil, err
	}

	return rv, nil
}

func parsePrivateKey(data []byte) (crypto.PrivateKey, error) {
	pemBlock, _ := pem.Decode(data)
	if pemBlock != nil {
		if !strings.HasSuffix(pemBlock.Type, "PRIVATE KEY") {
			return nil, fmt.Errorf("Found non-key PEM block.")
		}

		data = pemBlock.Bytes
	}

	if key, err := x509.ParsePKCS1PrivateKey(data); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(data); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, fmt.Errorf("Found unknown private key type in PKCS#8 wrapping.")
		}
	}
	if key, err := x509.ParseECPrivateKey(data); err == nil {
		return key, nil
	}

	return nil, errors.New("Failed to parse private key.")
}
