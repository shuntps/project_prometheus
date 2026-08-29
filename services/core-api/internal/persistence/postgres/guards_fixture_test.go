package postgres

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence"
)

// authority is a throwaway certificate authority. It is generated rather than
// pinned so the fixture cannot expire, and it never touches the account's home.
type authority struct {
	path string
	cert *x509.Certificate
	key  *rsa.PrivateKey
}

func newAuthority(t *testing.T) authority {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating the authority key failed: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "core-api test authority"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("signing the authority failed: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing the authority failed: %v", err)
	}
	path := filepath.Join(t.TempDir(), "root.crt")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("writing the authority failed: %v", err)
	}
	return authority{path: path, cert: cert, key: key}
}

// issue signs a server certificate for one name, so a handshake can be driven
// against a peer the configured authority does or does not vouch for.
func (a authority) issue(t *testing.T, dnsName string) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating the leaf key failed: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.cert, &key.PublicKey, a.key)
	if err != nil {
		t.Fatalf("signing the leaf failed: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func WriteTestCA(t *testing.T) string { return newAuthority(t).path }

// writeKeyPair writes a self-signed certificate and its key, for poisoning the
// client-certificate keys the driver would otherwise read from the home.
func writeKeyPair(t *testing.T, name string) (certPath, keyPath string) {
	t.Helper()
	ca := newAuthority(t)
	dir := t.TempDir()
	certPath = filepath.Join(dir, name+".crt")
	keyPath = filepath.Join(dir, name+".key")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(ca.key)})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("writing the certificate failed: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("writing the key failed: %v", err)
	}
	return certPath, keyPath
}

// openableSettings adds the pool bounds Open validates before anything else, so
// a refusal under test comes from the guard rather than from missing values.
func openableSettings(mode persistence.TLSMode, root string) persistence.Settings {
	settings := probeSettings(mode, root)
	settings.MaxConns = 4
	settings.MaxConnLifetime = time.Hour
	settings.MaxConnIdleTime = 30 * time.Minute
	settings.ConnectTimeout = time.Second
	settings.CheckTimeout = time.Second
	return settings
}

func probeSettings(mode persistence.TLSMode, root string) persistence.Settings {
	settings := persistence.Settings{TLSMode: mode}
	if mode.AuthenticatesServer() {
		settings.TLSRoot = persistence.TLSRoot(root)
	}
	return settings
}

func probeTarget() persistence.Target {
	return persistence.Target{
		Host:     persistence.NewSecret("db.example"),
		Port:     6432,
		User:     persistence.NewSecret("svc"),
		Password: persistence.NewSecret("pw"),
		Database: persistence.NewSecret("store"),
	}
}

func parsedQuery(t *testing.T, built string) url.Values {
	t.Helper()
	parsed, err := url.Parse(built)
	if err != nil {
		t.Fatalf("the rebuilt string is not a URL: %v", err)
	}
	return parsed.Query()
}

func poolFrom(t *testing.T, path string) *x509.CertPool {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the authority failed: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(body) {
		t.Fatal("the authority could not be parsed")
	}
	return pool
}

// handshake drives a real TLS handshake with the configuration the driver
// produced, against a peer this test chose to sign, name and serve.
func handshake(t *testing.T, client *tls.Config, server tls.Certificate) error {
	t.Helper()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{server},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("serving the peer failed: %v", err)
	}
	served := make(chan struct{})
	go func() {
		defer close(served)
		accepted, err := listener.Accept()
		if err != nil {
			return
		}
		_ = accepted.(*tls.Conn).Handshake()
		_ = accepted.Close()
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-served
	})

	dialed, err := tls.Dial("tcp", listener.Addr().String(), client)
	if err != nil {
		return err
	}
	return dialed.Close()
}

func systemPool(t *testing.T) *x509.CertPool {
	t.Helper()
	pool, err := x509.SystemCertPool()
	if err != nil {
		t.Skipf("the host certificate pool is unavailable: %v", err)
	}
	return pool
}

// authorityFrom reloads a written authority so a child process can issue leaves
// signed by the one its parent placed on the ambient certificate path.
func authorityFrom(t *testing.T, certPath, keyPath string) authority {
	t.Helper()
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("reading the authority failed: %v", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("reading the authority key failed: %v", err)
	}
	certBlock, _ := pem.Decode(certPEM)
	keyBlock, _ := pem.Decode(keyPEM)
	if certBlock == nil || keyBlock == nil {
		t.Fatal("the authority could not be decoded")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatalf("parsing the authority failed: %v", err)
	}
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatalf("parsing the authority key failed: %v", err)
	}
	return authority{path: certPath, cert: cert, key: key}
}
