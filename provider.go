package autocertLego

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"golang.org/x/crypto/acme/autocert"
	"k8s.io/klog/v2"
)

const (
	// ACMETLS1Protocol is the ALPN Protocol ID for the ACME-TLS/1 Protocol.
	ACMETLS1Protocol = "acme-tls/1"

	// defaultTLSPort is the port that the ProviderServer will default to
	// when no other port is provided.
	defaultTLSPort = "443"

	// idPeAcmeIdentifierV1 is the SMI Security for PKIX Certification Extension OID referencing the ACME extension.
	// Reference: https://tools.ietf.org/html/draft-ietf-acme-tls-alpn-07#section-6.1
)

var idPeAcmeIdentifierV1 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31}

// ProviderServer implements ChallengeProvider for `TLS-ALPN-01` challenge.
// It may be instantiated without using the NewProviderServer
// if you want only to use the default values.
type ProviderServer struct {
	sync.RWMutex
	port     string
	listener net.Listener
	inAction bool
	cache    autocert.Cache
}

// NewProviderServer creates a new ProviderServer on the selected interface and port.
// Setting iface and / or port to an empty string will make the server fall back to
// the "any" interface and port 443 respectively.
func NewProviderServer(port string, cache autocert.Cache) *ProviderServer {
	return &ProviderServer{
		port:     port,
		inAction: false,
		cache:    cache,
	}
}

func (s *ProviderServer) GetAddress() string {
	return net.JoinHostPort("", s.port)
}

// Present generates a certificate with a SHA-256 digest of the keyAuth provided
// as the acmeValidation-v1 extension value to conform to the ACME-TLS-ALPN spec.
func (s *ProviderServer) Present(domain, token, keyAuth string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	s.Lock()
	defer s.Unlock()
	if s.port == "" {
		// Fallback to port 443 if the port was not provided.
		s.port = defaultTLSPort
	}

	// Generate the challenge certificate using the provided keyAuth and domain.
	cert, err := ChallengeCert(domain, keyAuth)
	if err != nil {
		return err
	}

	ck := certKey{
		domain:  strings.TrimSuffix(domain, "."), // golang.org/issue/18114
		isToken: true,
	}
	err = cachePut(ctx, s.cache, ck, cert)
	if err != nil {
		klog.Error("autocertLego: %w", err)
	}
	s.inAction = true
	return nil
}

// CleanUp closes the HTTPS server.
func (s *ProviderServer) CleanUp(domain, token, keyAuth string) error {
	s.Lock()
	defer s.Unlock()
	s.inAction = false
	return nil
}

func (s *ProviderServer) LockAction() {
	s.Lock()
}

func (s *ProviderServer) IsAction() bool {
	return s.inAction
}

func (s *ProviderServer) UnlockAction() {
	s.Unlock()
}

// ChallengeBlocks returns PEM blocks (certPEMBlock, keyPEMBlock) with the acmeValidation-v1 extension
// and domain name for the `tls-alpn-01` challenge.
func ChallengeBlocks(domain, keyAuth string) ([]byte, []byte, error) {
	// Compute the SHA-256 digest of the key authorization.
	zBytes := sha256.Sum256([]byte(keyAuth))

	value, err := asn1.Marshal(zBytes[:sha256.Size])
	if err != nil {
		return nil, nil, err
	}

	// Add the keyAuth digest as the acmeValidation-v1 extension
	// (marked as critical such that it won't be used by non-ACME software).
	// Reference: https://tools.ietf.org/html/draft-ietf-acme-tls-alpn-07#section-3
	extensions := []pkix.Extension{
		{
			Id:       idPeAcmeIdentifierV1,
			Critical: true,
			Value:    value,
		},
	}

	// Generate a new RSA key for the certificates.
	tempPrivateKey, err := certcrypto.GeneratePrivateKey(certcrypto.RSA2048)
	if err != nil {
		return nil, nil, err
	}

	rsaPrivateKey := tempPrivateKey.(*rsa.PrivateKey)

	// Generate the PEM certificate using the provided private key, domain, and extra extensions.
	tempCertPEM, err := certcrypto.GeneratePemCert(rsaPrivateKey, domain, extensions)
	if err != nil {
		return nil, nil, err
	}

	// Encode the private key into a PEM format. We'll need to use it to generate the x509 keypair.
	rsaPrivatePEM := certcrypto.PEMEncode(rsaPrivateKey)

	return tempCertPEM, rsaPrivatePEM, nil
}

// ChallengeCert returns a certificate with the acmeValidation-v1 extension
// and domain name for the `tls-alpn-01` challenge.
func ChallengeCert(domain, keyAuth string) (*tls.Certificate, error) {
	tempCertPEM, rsaPrivatePEM, err := ChallengeBlocks(domain, keyAuth)
	if err != nil {
		return nil, err
	}

	cert, err := tls.X509KeyPair(tempCertPEM, rsaPrivatePEM)
	if err != nil {
		return nil, err
	}

	return &cert, nil
}
