package autocertLego

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/foomo/tlsconfig"
	"github.com/go-acme/lego/v4/certificate"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/idna"
	"k8s.io/klog/v2"
)

var Default = &Manager{
	EMail:     "",
	Directory: "https://acme-v02.api.letsencrypt.org/directory",
}

type HostPolicy func(ctx context.Context, host string) error

// certKey is the key by which certificates are tracked in state, renewal and cache.
type certKey struct {
	domain  string // without trailing dot
	isRSA   bool   // RSA cert for legacy clients (as opposed to default ECDSA)
	isToken bool   // tls-based challenge token cert; key type is undefined regardless of isRSA
}

type Manager struct {
	EMail              string
	Directory          string
	sslUser            SSLUser
	whitelistedDomains []string
	provider           *ProviderServer
	HostPolicy         HostPolicy
	DirCache           autocert.Cache
}

// TLSConfig creates a new TLS config suitable for net/http.Server servers,
// supporting HTTP/2 and the tls-alpn-01 ACME challenge type.
func (m *Manager) TLSConfig() *tls.Config {
	tlsConf := tlsconfig.NewServerTLSConfig(tlsconfig.TLSModeServerStrict)
	tlsConf.NextProtos = []string{
		"h2", "http/1.1", // enable HTTP/2
		acme.ALPNProto, // enable tls-alpn ACME challenges
	}
	tlsConf.GetCertificate = m.GetCertificateFunc
	return tlsConf
}

func (m *Manager) isALPNRequest(clientHello *tls.ClientHelloInfo) bool {
	return len(clientHello.SupportedProtos) == 1 && clientHello.SupportedProtos[0] == acme.ALPNProto
}

func (m *Manager) GetCertificateFunc(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := clientHello.ServerName
	if name == "" {
		return nil, errors.New("autocertLego: missing server name")
	}

	// Due to the "σςΣ" problem (see https://unicode.org/faq/idn.html#22), we can't use
	// idna.Punycode.ToASCII (or just idna.ToASCII) here.
	name, err := idna.Lookup.ToASCII(name)
	if err != nil {
		return nil, errors.New("autocertLego: server name contains invalid character")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	if err := m.hostPolicy()(ctx, name); err != nil {
		return nil, err
	}

	if m.isALPNRequest(clientHello) {
		klog.Infof("autocertLego: See ALPN-Request for %s", name)
		m.provider.Lock()
		defer m.provider.Unlock()
		for {
			ck := certKey{
				domain:  name,
				isToken: true,
			}
			if klog.V(3).Enabled() {
				klog.Infof("autocertLego: ask cache for %v", ck)
			}
			cert, err := cacheGet(ctx, m.DirCache, ck)
			if err == nil {
				return cert, nil
			}
		}
	}

	// regular domain
	ck := certKey{
		domain: strings.TrimSuffix(name, "."), // golang.org/issue/18114
		isRSA:  !supportsECDSA(clientHello),
	}
	cert, err := m.cert(ctx, ck)
	if err == nil {
		return cert, nil
	}

	if err != autocert.ErrCacheMiss {
		return nil, err
	}
	// first-time
	klog.Infof("autocertLego: Create Cert for %s", name)
	connection := clientHello.Conn
	hostport := connection.LocalAddr().String()
	_, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, err
	}
	cert, err = m.createCert(ctx, name, port)
	if err != nil {
		return nil, err
	}
	cachePut(ctx, m.DirCache, ck, cert)
	return cert, nil
}

func (m *Manager) cert(ctx context.Context, ck certKey) (*tls.Certificate, error) {
	cert, err := cacheGet(ctx, m.DirCache, ck)
	if err != nil {
		klog.Infof("autocertLego: Error cert/cacheGet: %w", err)
		return nil, err
	}
	_, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("autocertLego: private key cannot sign")
	}
	return cert, nil
}

func (m *Manager) createCert(ctx context.Context, domain string, port string) (*tls.Certificate, error) {
	u, err := getUser(ctx, m.EMail, m.DirCache)
	if err != nil {
		return nil, errors.New("autocertLego: failed to get ACME user: " + err.Error())
	}

	if m.provider == nil {
		m.provider = NewProviderServer(port, m.DirCache)
	}

	// get ACME Client
	clientConfiguration := &ClientConfiguration{
		SSLUser:        u,
		DirectoryURL:   m.Directory,
		TLSAddress:     net.JoinHostPort(domain, port),
		ProviderServer: m.provider,
		Cache:          m.DirCache,
	}
	client, err := createClient(ctx, clientConfiguration)
	if err != nil {
		return nil, errors.New("autocertLego: failed to create lego.Client: " + err.Error())
	}

	// bundle CA with certificate to avoid "transport: x509: certificate signed by unknown authority" error
	request := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}

	// Obtain a new certificate
	// The acme library takes care of completing the challenges to obtain the certificate(s).
	// The domains must resolve to this machine or you have to use the DNS challenge.
	cert, err := client.Certificate.Obtain(request)
	if err != nil {
		return nil, errors.New("autocertLego: failed to obtain cert: " + err.Error())
	}

	klog.Infof("autocertLego: client obtained cert for domain: ", cert.Domain)
	crt, err := tls.X509KeyPair(cert.Certificate, cert.PrivateKey)
	if err != nil {
		return nil, err
	}
	return &crt, nil
}

func (m *Manager) hostPolicy() HostPolicy {
	if m.HostPolicy != nil {
		return m.HostPolicy
	}
	return defaultHostPolicy
}

func HostWhitelist(hosts ...string) HostPolicy {
	whitelist := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		if h, err := idna.Lookup.ToASCII(h); err == nil {
			whitelist[h] = true
		}
	}
	return func(_ context.Context, host string) error {
		if !whitelist[host] {
			return fmt.Errorf("autocertLego: host %q not configured in HostWhitelist", host)
		}
		return nil
	}
}

func defaultHostPolicy(context.Context, string) error {
	return nil
}

func encodeECDSAKey(w io.Writer, key *ecdsa.PrivateKey) error {
	b, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	pb := &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	return pem.Encode(w, pb)
}

func encodeRSAKey(w io.Writer, key *rsa.PrivateKey) error {
	b := x509.MarshalPKCS1PrivateKey(key)
	pb := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: b}
	return pem.Encode(w, pb)
}

func (c certKey) String() string {
	if c.isToken {
		return c.domain + "+token"
	}
	if c.isRSA {
		return c.domain + "+rsa"
	}
	return c.domain
}

// Attempt to parse the given private key DER block. OpenSSL 0.9.8 generates
// PKCS#1 private keys by default, while OpenSSL 1.0.0 generates PKCS#8 keys.
// OpenSSL ecparam generates SEC1 EC private keys for ECDSA. We try all three.
//
// Inspired by parsePrivateKey in crypto/tls/tls.go.
func parsePrivateKey(der []byte) (crypto.Signer, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey:
			return key, nil
		case *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("autocertLego: unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, errors.New("autocertLego: failed to parse private key")
}

func supportsECDSA(hello *tls.ClientHelloInfo) bool {
	// The "signature_algorithms" extension, if present, limits the key exchange
	// algorithms allowed by the cipher suites. See RFC 5246, section 7.4.1.4.1.
	if hello.SignatureSchemes != nil {
		ecdsaOK := false
	schemeLoop:
		for _, scheme := range hello.SignatureSchemes {
			const tlsECDSAWithSHA1 tls.SignatureScheme = 0x0203 // constant added in Go 1.10
			switch scheme {
			case tlsECDSAWithSHA1, tls.ECDSAWithP256AndSHA256,
				tls.ECDSAWithP384AndSHA384, tls.ECDSAWithP521AndSHA512:
				ecdsaOK = true
				break schemeLoop
			}
		}
		if !ecdsaOK {
			return false
		}
	}
	if hello.SupportedCurves != nil {
		ecdsaOK := false
		for _, curve := range hello.SupportedCurves {
			if curve == tls.CurveP256 {
				ecdsaOK = true
				break
			}
		}
		if !ecdsaOK {
			return false
		}
	}
	for _, suite := range hello.CipherSuites {
		switch suite {
		case tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305:
			return true
		}
	}
	return false
}
