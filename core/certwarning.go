package core

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"strings"
)

type Warning interface {
	Title() string
	Description() string
}

type ExpirationWarning struct {
	c *Certificate
}

func (w ExpirationWarning) Title() string {
	return "The certificate will expire soon."
}

func (w ExpirationWarning) Description() string {
	return formatDescription(`
This certificate is set to expire in %.2f days, which is less than 3
months. You should probably prepare to renew this certificate (or any
descendant certificate) soon.
`, w.c.DaysToExpire())
}

func TryExpirationWarning(c *Certificate) Warning {
	if c.DaysToExpire() < 90 {
		return ExpirationWarning{c: c}
	} else {
		return nil
	}
}

type ObsoleteAlgorithmWarning struct {
	c *Certificate
}

func (w ObsoleteAlgorithmWarning) Title() string {
	return "Certificate signed with obsolete algorithm."
}

func (w ObsoleteAlgorithmWarning) Description() string {
	return formatDescription(`
This certificate was signed using %s, which is considered a broken/weak
algorithm. Modern browsers will tend to reject certificates signed in
this manner, and you should consider replacing this certificate.
`, w.c.ReadableSignatureAlgorithm())
}

func TryObsoleteAlgorithmWarning(c *Certificate) Warning {
	var isObsoleteAlgorithm bool
	switch c.Certificate.SignatureAlgorithm {
	case x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1,
		x509.MD2WithRSA, x509.MD5WithRSA:
		isObsoleteAlgorithm = true
	default:
		isObsoleteAlgorithm = false
	}
	if !c.IsBundled() && isObsoleteAlgorithm {
		return ObsoleteAlgorithmWarning{c: c}
	} else {
		return nil
	}
}

type KeyTooShortWarning struct {
	c *Certificate
}

func (w KeyTooShortWarning) Title() string {
	return "Key size is too short."
}

func (w KeyTooShortWarning) Description() string {
	return formatDescription(`
This certificate has a key that's too short (%d bits) for today's
standards. RSA keys should have at least 2048 bits, and ECDSA curves
should respect the requirements established by the CA/B forum. You
should probably replace this certificate.
`, w.c.ReadableKeyBitLength())
}

func TryKeyTooShortWarning(c *Certificate) Warning {
	rsaPubKey, ok := c.Certificate.PublicKey.(*rsa.PublicKey)
	if ok && rsaPubKey.N.BitLen() < 2048 && !c.IsBundled() {
		return KeyTooShortWarning{c: c}
	} else {
		return nil
	}
}

func formatDescription(format string, a ...interface{}) string {
	return strings.Replace(strings.Trim(fmt.Sprintf(format, a...), " \n"), "\n", " ", -1)
}

var warningTriers = []func(*Certificate) Warning{
	TryExpirationWarning,
	TryObsoleteAlgorithmWarning,
	TryKeyTooShortWarning,
}

func (c *Certificate) Warnings() []Warning {
	rv := []Warning{}
	for _, trier := range warningTriers {
		w := trier(c)
		if w != nil {
			rv = append(rv, w)
		}
	}
	return rv
}
