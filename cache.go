package autocertLego

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/acme/autocert"
	"k8s.io/klog/v2"
)

var ErrNoCache = errors.New("simplecert: no cache provides")

func cachePut(ctx context.Context, cache autocert.Cache, domain certKey, tlscert *tls.Certificate) error {
	if cache == nil {
		return fmt.Errorf("Cache is nil")
	}

	// contains PEM-encoded data
	var buf bytes.Buffer

	// private
	switch key := tlscert.PrivateKey.(type) {
	case *ecdsa.PrivateKey:
		if err := encodeECDSAKey(&buf, key); err != nil {
			return err
		}
	case *rsa.PrivateKey:
		b := x509.MarshalPKCS1PrivateKey(key)
		pb := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: b}
		if err := pem.Encode(&buf, pb); err != nil {
			return err
		}
	default:
		return errors.New("acme/autocert: unknown private key type")
	}

	// public
	for _, b := range tlscert.Certificate {
		pb := &pem.Block{Type: "CERTIFICATE", Bytes: b}
		if err := pem.Encode(&buf, pb); err != nil {
			return err
		}
	}

	if klog.V(2).Enabled() {
		klog.Infof("autocertLego: cache.Put(%s)", domain.String())
	}
	return cache.Put(ctx, domain.String(), buf.Bytes())
}

// cacheGet always returns a valid certificate, or an error otherwise.
// If a cached certificate exists but is not valid, ErrCacheMiss is returned.
func cacheGet(ctx context.Context, cache autocert.Cache, ck certKey) (*tls.Certificate, error) {
	if cache == nil {
		return nil, ErrNoCache
	}
	data, err := cache.Get(ctx, ck.String())
	if err != nil {
		return nil, err
	}

	// private
	priv, pub := pem.Decode(data)
	if priv == nil || !strings.Contains(priv.Type, "PRIVATE") {
		return nil, autocert.ErrCacheMiss
	}
	privKey, err := parsePrivateKey(priv.Bytes)
	if err != nil {
		return nil, err
	}

	// public
	var pubDER [][]byte
	for len(pub) > 0 {
		var b *pem.Block
		b, pub = pem.Decode(pub)
		if b == nil {
			break
		}
		pubDER = append(pubDER, b.Bytes)
	}
	if len(pub) > 0 {
		// Leftover content not consumed by pem.Decode. Corrupt. Ignore.
		return nil, autocert.ErrCacheMiss
	}

	// verify and create TLS cert
	leaf, err := validCert(ck, pubDER, privKey, time.Now())
	if err != nil {
		return nil, autocert.ErrCacheMiss
	}
	tlscert := &tls.Certificate{
		Certificate: pubDER,
		PrivateKey:  privKey,
		Leaf:        leaf,
	}
	return tlscert, nil
}

// validCert parses a cert chain provided as der argument and verifies the leaf and der[0]
// correspond to the private key, the domain and key type match, and expiration dates
// are valid. It doesn't do any revocation checking.
//
// The returned value is the verified leaf cert.
func validCert(ck certKey, der [][]byte, key crypto.Signer, now time.Time) (leaf *x509.Certificate, err error) {
	// parse public part(s)
	var n int
	for _, b := range der {
		n += len(b)
	}
	pub := make([]byte, n)
	n = 0
	for _, b := range der {
		n += copy(pub[n:], b)
	}
	x509Cert, err := x509.ParseCertificates(pub)
	if err != nil || len(x509Cert) == 0 {
		return nil, errors.New("autocertLego: no public key found")
	}
	// verify the leaf is not expired and matches the domain name
	leaf = x509Cert[0]
	if now.Before(leaf.NotBefore) {
		return nil, errors.New("autocertLego: certificate is not valid yet")
	}

	if now.After(leaf.NotAfter) && !ck.isToken {
		return nil, fmt.Errorf("autocertLego: expired certificate: %s (now is %s)", leaf.NotAfter, time.Now())
	}
	if err := leaf.VerifyHostname(ck.domain); err != nil {
		return nil, err
	}
	// ensure the leaf corresponds to the private key and matches the certKey type
	switch pub := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		prv, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("autocertLego: private key type does not match public key type")
		}
		if pub.N.Cmp(prv.N) != 0 {
			return nil, errors.New("autocertLego: private key does not match public key")
		}
		if !ck.isRSA && !ck.isToken {
			return nil, errors.New("autocertLego: private key type does not match expected value")
		}
	case *ecdsa.PublicKey:
		prv, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("autocertLego: private key type does not match public key type")
		}
		if pub.X.Cmp(prv.X) != 0 || pub.Y.Cmp(prv.Y) != 0 {
			return nil, errors.New("autocertLego: private key does not match public key")
		}
		if ck.isRSA && !ck.isToken {
			return nil, errors.New("autocertLego: public key type does not match expected value")
		}
	default:
		return nil, errors.New("autocertLego: unknown public key algorithm")
	}
	return leaf, nil
}
