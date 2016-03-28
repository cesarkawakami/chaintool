package core

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func (c *Certificate) PrivateKeyToPEM() ([]byte, error) {
	var der []byte
	var err error
	var pemType string
	switch pKey := c.PrivateKey.(type) {
	case *ecdsa.PrivateKey:
		pemType = "EC"
		der, err = x509.MarshalECPrivateKey(pKey)
	case *rsa.PrivateKey:
		pemType = "RSA"
		der = x509.MarshalPKCS1PrivateKey(pKey)
	default:
		return nil, fmt.Errorf("Unknown private key type: %T", pKey)
	}
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  pemType + " PRIVATE KEY",
		Bytes: der,
	}), nil
}

func (c *Certificate) CertificateToPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c.Certificate.Raw,
	})
}

func (c *CertificateChain) IntermediatesToPEM() []byte {
	buf := &bytes.Buffer{}
	for _, cert := range c.Intermediates {
		buf.Write(cert.CertificateToPEM())
	}
	return buf.Bytes()
}
