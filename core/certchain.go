package core

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/service/iam"
)

type CertificateChain struct {
	Leaf          *Certificate
	Intermediates []*Certificate
}

func FetchCertificateChain(host, port string) (*CertificateChain, error) {
	tlsClientConfig := &tls.Config{
		RootCAs:            MustCertPool(),
		InsecureSkipVerify: true,
	}
	conn, err := tls.Dial("tcp", net.JoinHostPort(host, port), tlsClientConfig)
	if err != nil {
		return nil, fmt.Errorf("Unable to establish connection to server: %s", err)
	}

	connState := conn.ConnectionState()

	rv := &CertificateChain{}
	isFirst := true
	for _, cert := range connState.PeerCertificates {
		if isFirst {
			isFirst = false
			rv.Leaf = &Certificate{
				Certificate: cert,
			}
		} else {
			rv.Intermediates = append(rv.Intermediates, &Certificate{
				Certificate: cert,
			})
		}
	}
	return rv, nil
}

func ChainFromAWS(awsCertificate *iam.ServerCertificate) (*CertificateChain, error) {
	rv := &CertificateChain{}

	if awsCertificate.CertificateBody == nil {
		return nil, fmt.Errorf("AWS Certificate doesn't have a body.")
	}
	leafX509, err := parseCertificate([]byte(*awsCertificate.CertificateBody))
	if err != nil {
		return nil, fmt.Errorf("Unable to parse certificate body: %s", err)
	}
	rv.Leaf = &Certificate{
		Certificate: leafX509,
	}

	if awsCertificate.CertificateChain != nil {
		intermediatesX509, err := parseCertificates([]byte(*awsCertificate.CertificateChain))
		if err != nil {
			return nil, fmt.Errorf("Unable to parse intermediate certificates: %s", err)
		}
		for _, cert := range intermediatesX509 {
			rv.Intermediates = append(rv.Intermediates, &Certificate{
				Certificate: cert,
			})
		}
	}

	return rv, nil
}

func ChainFromCertificateAndIntermediatesData(
	leaf *Certificate,
	intermediatesData []byte,
) (*CertificateChain, error) {
	rv := &CertificateChain{
		Leaf: leaf,
	}

	intermediatesX509, err := parseCertificates(intermediatesData)
	intermediatesPool := x509.NewCertPool()
	if err != nil {
		return nil, fmt.Errorf("Unable to parse intermediate certificates: %s", err)
	}
	for _, cert := range intermediatesX509 {
		intermediatesPool.AddCert(cert)
	}

	verifiedChains, err := leaf.Certificate.Verify(x509.VerifyOptions{
		Roots:         MustCertPool(),
		CurrentTime:   time.Now(),
		Intermediates: intermediatesPool,
	})
	switch err := err.(type) {
	case nil:
		break
	case x509.UnknownAuthorityError:
		return nil, UnknownAuthorityError{}
	default:
		return nil, fmt.Errorf("Unable to verify certificate chain: %s", err)
	}

	isLeaf := true
	for _, x509Cert := range verifiedChains[0] {
		if isLeaf {
			isLeaf = false
			continue
		}

		cert := &Certificate{
			Certificate: x509Cert,
		}

		if cert.IsBundled() {
			break
		}

		rv.Intermediates = append(rv.Intermediates, cert)
	}

	return rv, nil
}

func ChainFromCertificateAndInternet(leaf *Certificate) (*CertificateChain, error) {
	rv := &CertificateChain{
		Leaf: leaf,
	}

	isLeafCert := true
	currentCert := leaf
	var err error
	for {
		if currentCert.IsBundled() {
			break
		}

		if !isLeafCert {
			rv.Intermediates = append(rv.Intermediates, currentCert)
		}
		isLeafCert = false

		if len(currentCert.Certificate.IssuingCertificateURL) == 0 {
			return nil, fmt.Errorf(
				"Error fetching intermediates: cert for %s doesn't point to parent",
				currentCert.ReadableSubject())
		}

		success := false
		err = fmt.Errorf(
			"Error fetching intermediates: cert for %s doesn't point to parent",
			currentCert.ReadableSubject())
		for _, url := range currentCert.Certificate.IssuingCertificateURL {
			currentCert, err = CertificateFromURL(url)
			if err == nil {
				success = true
				break
			}
		}
		if !success {
			return nil, fmt.Errorf("Unable to fetch next cert in chain: %s", err)
		}
	}

	return rv, nil
}

func ChainFromFullChainData(chainData []byte) (*CertificateChain, error) {
	certsX509, err := parseCertificates(chainData)
	if err != nil {
		return nil, fmt.Errorf("Unable to parse certificates: %s", err)
	}

	if len(certsX509) <= 0 {
		return nil, fmt.Errorf("Found no certificates in the given file.")
	}

	rv := &CertificateChain{}
	rv.Leaf = &Certificate{
		Certificate: certsX509[0],
	}

	for _, cert := range certsX509[1:] {
		rv.Intermediates = append(rv.Intermediates, &Certificate{
			Certificate: cert,
		})
	}

	return rv, nil
}

func (c *CertificateChain) InfoLines(wrapLength int) *Lines {
	lines := NewLines()

	if c.Leaf != nil {
		lines.Print("Leaf Certificate:")
		lines.AppendLines(c.Leaf.InfoLines(wrapLength - 2).IndentedBy("  "))
	} else {
		lines.Print("No Leaf Certificate Present")
	}

	for index, cert := range c.Intermediates {
		lines.Print("Intermediate #%d:", index+1)
		lines.AppendLines(cert.InfoLines(wrapLength - 2).IndentedBy("  "))
	}

	return lines
}

func (c *CertificateChain) Verify(dnsName string) error {
	verifyOptions := x509.VerifyOptions{
		Roots:         MustCertPool(),
		CurrentTime:   time.Now(),
		Intermediates: x509.NewCertPool(),
	}

	if dnsName != "" {
		verifyOptions.DNSName = dnsName
	}

	for _, cert := range c.Intermediates {
		verifyOptions.Intermediates.AddCert(cert.Certificate)
	}

	_, err := c.Leaf.Certificate.Verify(verifyOptions)
	switch err := err.(type) {
	case nil:
		return nil
	case x509.HostnameError:
		return HostnameMismatchError{
			Certificate: c.Leaf,
			Hostname:    dnsName,
		}
	case x509.UnknownAuthorityError:
		return UnknownAuthorityError{}
	default:
		return err
	}
}

type HostnameMismatchError struct {
	Certificate *Certificate
	Hostname    string
}

func (e HostnameMismatchError) Error() string {
	nameLines := []string{}
	for _, certName := range e.Certificate.Certificate.DNSNames {
		nameLines = append(nameLines, "  - "+certName)
	}
	return formatVerifyError(`
The received certificate, which is valid for:

%s

Doesn't match the target hostname, which is:

    %s

You're probably using the wrong certificate for this use.
`,
		strings.Join(nameLines, "\n"),
		e.Hostname,
	)
}

type UnknownAuthorityError struct{}

func (e UnknownAuthorityError) Error() string {
	return formatVerifyError(`
Unable to verify the certificate chain up to trusted bundled root CA
certificate. This can be due to:

  - Using self-signed certificates

  - The server-side not serving the intermediate certificates needed to
    build a trust chain up to a bundled certificate

This should probably be corrected if you want your site to work for the
majority of users. In the second case, you might not see errors at
first, since modern browsers cache intermediate certificates, but you'll
see intermittent connection problems, so this should be solved anyway.
`)
}

func formatVerifyError(format string, a ...interface{}) string {
	return strings.Trim(fmt.Sprintf(format, a...), " \n")
}
