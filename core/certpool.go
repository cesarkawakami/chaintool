package core

import (
	"crypto/x509"
	"fmt"

	"github.com/certifi/gocertifi"
)

var certPoolCache *x509.CertPool

func CertPool() (*x509.CertPool, error) {
	if certPoolCache == nil {
		var err error
		certPoolCache, err = gocertifi.CACerts()
		if err != nil {
			certPoolCache = nil
			return nil, fmt.Errorf("Unable to load certificates from built-in store: %s", err)
		}
	}
	return certPoolCache, nil
}

func MustCertPool() *x509.CertPool {
	if rv, err := CertPool(); err != nil {
		panic(err)
	} else {
		return rv
	}
}

var certPoolSubjectSetCache map[string]struct{}

func certPoolSubjectSet() map[string]struct{} {
	if certPoolSubjectSetCache == nil {
		certPoolSubjectSetCache = map[string]struct{}{}
		for _, subject := range MustCertPool().Subjects() {
			certPoolSubjectSetCache[string(subject)] = struct{}{}
		}
	}
	return certPoolSubjectSetCache
}

func certInPool(cert *x509.Certificate) bool {
	_, ok := certPoolSubjectSet()[string(cert.RawSubject)]
	return ok
}
