//go:build linux

package ktls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// selfSigned generates a throwaway self-signed ECDSA P-256 certificate valid
// for localhost. The *testing.T is only used for error reporting.
func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()

	return selfSignedTB(t.Helper, t.Fatal)
}

// selfSignedB is the benchmark-compatible variant: it reports errors via b.Fatal
// instead of t.Fatal so benchmarks can reuse the same certificate generation.
func selfSignedB(b testing.TB) tls.Certificate {
	b.Helper()

	return selfSignedTB(b.Helper, b.Fatal)
}

// selfSignedTB does the actual certificate generation shared by selfSigned and
// selfSignedB; the fatal callback lets it work for both *testing.T and *testing.B.
func selfSignedTB(_ func(), fatal func(args ...any)) tls.Certificate {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		fatal(err)
	}

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func selfSignedRSA(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-rsa"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
