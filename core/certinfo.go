package core

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"time"
)

func (c *Certificate) ReadableSubject() string {
	return fmt.Sprintf("%x (%s)", c.Certificate.SubjectKeyId[:4], c.Certificate.Subject.CommonName)
}

func (c *Certificate) ReadableIssuer() string {
	if c.Certificate.AuthorityKeyId == nil {
		return "Unsigned"
	}

	if bytes.Compare(c.Certificate.AuthorityKeyId, c.Certificate.SubjectKeyId) == 0 {
		return "Self-signed"
	}

	return fmt.Sprintf("%x (%s)", c.Certificate.AuthorityKeyId[:4], c.Certificate.Issuer.CommonName)
}

func (c *Certificate) ReadableExpiration() string {
	return fmt.Sprintf("%.2f days (%s)", c.DaysToExpire(), c.Certificate.NotAfter)
}

func (c *Certificate) ReadableSignatureAlgorithm() string {
	return c.Certificate.SignatureAlgorithm.String()
}

func (c *Certificate) ReadablePublicKeyAlgorithm() string {
	mapping := map[x509.PublicKeyAlgorithm]string{
		x509.RSA:   "RSA",
		x509.DSA:   "DSA",
		x509.ECDSA: "ECDSA",
	}

	name, ok := mapping[c.Certificate.PublicKeyAlgorithm]
	if ok {
		return name
	} else {
		return "Unknown algorithm"
	}
}

func (c *Certificate) ReadableKeyBitLength() string {
	switch publicKey := c.Certificate.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("%d", publicKey.N.BitLen())
	case *ecdsa.PublicKey:
		return fmt.Sprintf("%d", publicKey.X.BitLen())
	default:
		return "[error: unsupported signature algorithm]"
	}
}

func (c *Certificate) IsBundled() bool {
	return certInPool(c.Certificate)
}

func (c *Certificate) DaysToExpire() float64 {
	return c.Certificate.NotAfter.Sub(time.Now()).Hours() / 24
}

func (c *Certificate) InfoLines(wrapLength int) *Lines {
	lines := NewLines()

	lines.Print("Subject:     %s", c.ReadableSubject())
	lines.Print("Issuer:      %s", c.ReadableIssuer())
	lines.Print("Bundled in")
	lines.Print("browsers?    %v", c.IsBundled())
	lines.Print("Expires in:  %s", c.ReadableExpiration())
	lines.Print("Sig. Algo.:  %s", c.ReadableSignatureAlgorithm())
	lines.Print("Key Algo.:   %s", c.ReadablePublicKeyAlgorithm())
	lines.Print("Bit Length:  %s", c.ReadableKeyBitLength())
	lines.AppendLines(c.domainLines(wrapLength))
	lines.AppendLines(c.warningLines(wrapLength))

	return lines
}

func (c *Certificate) warningLines(wrapLength int) *Lines {
	lines := NewLines()

	lines.Print("Warnings:")

	warnings := c.Warnings()

	if len(warnings) <= 0 {
		lines.Print("  - None. Yay!")
		return lines
	}

	for _, warning := range warnings {
		subIndent := "  - "
		for _, line := range wordWrapLines(warning.Description(), wrapLength-4) {
			lines.Print("%s%s", subIndent, line)
			subIndent = "    "
		}
	}

	return lines
}

func (c *Certificate) domainLines(wrapLength int) *Lines {
	lines := NewLines()

	prefix1 := "Valid for:   "
	prefix2 := "             "

	for _, name := range c.Certificate.DNSNames {
		lines.Print("%s%s", prefix1, name)
		prefix1 = prefix2
	}

	return lines
}
