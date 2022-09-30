package certretrieval

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

const (
	tmpdir  = "../../tmp"
	keysize = 768
	certUrl = "/v1/%s/issue/client"
)

type MiniCa struct {
	serialNumber *big.Int
	caCert       *x509.Certificate
	caKey        *rsa.PrivateKey
}

func newCA(t *testing.T) *MiniCa {
	privateKey, err := rsa.GenerateKey(rand.Reader, keysize)
	if err != nil {
		t.Fatalf("Failed to create ca key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Issuer: pkix.Name{
			CommonName: "testca",
		},
		IsCA:                  true,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	cert, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}
	caCert := &x509.Certificate{Raw: cert, PublicKey: &privateKey.PublicKey}

	return &MiniCa{serialNumber: template.SerialNumber, caCert: caCert, caKey: privateKey}
}

func (ca *MiniCa) createServerCert() (*x509.Certificate, *rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, keysize)
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber: ca.serialNumber.Add(ca.serialNumber, big.NewInt(1)),
		Issuer: pkix.Name{
			CommonName: "test server",
		},
		IsCA:        false,
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(1 * time.Hour),
		KeyUsage:    x509.KeyUsageDataEncipherment | x509.KeyUsageKeyAgreement,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	cert, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, ca.caKey)
	if err != nil {
		return nil, nil, err
	}
	serverCert := &x509.Certificate{Raw: cert, PublicKey: &privateKey.PublicKey}
	return serverCert, privateKey, nil
}

func (ca *MiniCa) createClientCert() (*x509.Certificate, *rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, keysize)
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber: ca.serialNumber.Add(ca.serialNumber, big.NewInt(1)),
		Issuer: pkix.Name{
			CommonName: "client",
		},
		IsCA:        false,
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDataEncipherment | x509.KeyUsageKeyAgreement,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	cert, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, ca.caKey)
	if err != nil {
		return nil, nil, err
	}
	serverCert := &x509.Certificate{Raw: cert, PublicKey: &privateKey.PublicKey}
	return serverCert, privateKey, nil
}

func (ca *MiniCa) createTlsConfig() (*tls.Config, string, error) {
	cert, key, err := ca.createServerCert()
	if err != nil {
		return nil, "", err
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.caCert)
	config := &tls.Config{
		Rand:         rand.Reader,
		Time:         time.Now,
		Certificates: []tls.Certificate{{Certificate: [][]byte{cert.Raw}, PrivateKey: key}},
		RootCAs:      pool,
	}

	builder := strings.Builder{}
	pem.Encode(&builder, &pem.Block{Type: "CERTIFICATE", Bytes: ca.caCert.Raw})
	caCert := builder.String()

	return config, caCert, nil
}

func (ca *MiniCa) createServer(t *testing.T, handler http.Handler) (*httptest.Server, string) {
	server := httptest.NewUnstartedServer(handler)
	tlsConfig, caCert, err := ca.createTlsConfig()
	if err != nil {
		t.Fatalf("Failed to create tls config: %v", err)
	}
	server.TLS = tlsConfig
	server.StartTLS()
	return server, caCert
}

func certificateHandler(t *testing.T, ca *MiniCa, callCounter *int) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		(*callCounter)++
		encoder := json.NewEncoder(rw)

		cert, key, err := ca.createClientCert()
		if err != nil {
			t.Fatalf("Failed to create client certificate: %v", err)
		}
		builder := strings.Builder{}
		if err := pem.Encode(&builder, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
			t.Fatalf("Failed to encode cert: %v", err)
		}
		certText := builder.String()

		builder.Reset()
		if err := pem.Encode(&builder, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
			t.Fatalf("Failed to encode cert: %v", err)
		}
		keyText := builder.String()

		builder.Reset()
		if err := pem.Encode(&builder, &pem.Block{Type: "CERTIFICATE", Bytes: ca.caCert.Raw}); err != nil {
			t.Fatalf("Failed to encode cert: %v", err)
		}
		caText := builder.String()

		response := CertificateResponse{
			RequestId:     uuid.New().String(),
			LeaseDuration: UnixTime(time.Now().Add(24 * time.Hour)),
			Renewable:     false,
			Data: CertificateData{
				Certificate:    certText,
				Expiration:     UnixTime(time.Now().Add(12 * time.Hour)),
				IssuingCa:      caText,
				PrivateKey:     keyText,
				SerialNumber:   cert.Issuer.SerialNumber,
				PrivateKeyType: "rsa",
			},
		}
		if err := encoder.Encode(response); err != nil {
			t.Fatalf("Failed to encode response: %v", err)
		}
	}
}

func setup(t *testing.T) {
	if err := os.RemoveAll(tmpdir); err != nil && !os.IsNotExist(err) {
		t.Fatalf("Failed to remove tmp directory %q: %v", tmpdir, err)
	}

	if err := os.MkdirAll(tmpdir, 0755); err != nil {
		t.Fatalf("Failed to create diretory %q: %v", tmpdir, err)
	}

	if err := os.WriteFile(tmpdir+"/token.txt", []byte("dummy token"), 0644); err != nil {
		t.Fatalf("Failed create dummy token: %v", err)
	}

}
func TestRetrieval(t *testing.T) {
	setup(t)
	ca := newCA(t)

	PKI := "pki"
	var invocations int
	mux := http.NewServeMux()
	mux.HandleFunc(fmt.Sprintf(certUrl, PKI), certificateHandler(t, ca, &invocations))
	server, caCert := ca.createServer(t, mux)
	if err := os.WriteFile(tmpdir+"/server-ca.crt", []byte(caCert), 0755); err != nil {
		t.Fatal(err)
	}

	config := Config{
		Tokenfile:   tmpdir + "/token.txt",
		Address:     server.URL,
		Role:        "client",
		Name:        "edge0.edgefarm.io",
		ServerCA:    tmpdir + "/server-ca.crt",
		PKI:         PKI,
		OutCAfile:   tmpdir + "/ca.crt",
		OutCertfile: tmpdir + "/client.crt",
		OutKeyfile:  tmpdir + "/client.key",
	}

	cr, err := New(config)
	if err != nil {
		t.Fatalf("Failed to create cert retrieval: %v", err)
	}

	if err := cr.Retrieve(); err != nil {
		t.Fatalf("Failed to retrieve: %v", err)
	}

	var data []byte
	data, _ = os.ReadFile(config.OutCAfile)

	if expected := 1; expected != invocations {
		t.Errorf("Wrong number of invocations, expected %d but got %d", expected, invocations)
	}

	if !strings.HasPrefix(string(data), "-----BEGIN CERTIFICATE-----") {
		t.Errorf("Wrong ca. Expected cert but got %s", data)
	}
	data, _ = os.ReadFile(config.OutCertfile)
	if !strings.HasPrefix(string(data), "-----BEGIN CERTIFICATE-----") {
		t.Errorf("Wrong cert. Expected cert but got %s", data)
	}
	data, _ = os.ReadFile(config.OutKeyfile)
	if !strings.HasPrefix(string(data), "-----BEGIN RSA PRIVATE KEY-----") {
		t.Errorf("Wrong key. Expected private key but got %s", data)
	}
}

func TestConditionalRetrieval(t *testing.T) {
	setup(t)
	ca := newCA(t)
	PKI := "pki"
	mux := http.NewServeMux()
	var invocations int
	mux.HandleFunc(fmt.Sprintf(certUrl, PKI), certificateHandler(t, ca, &invocations))
	server, caCert := ca.createServer(t, mux)
	if err := os.WriteFile(tmpdir+"/server-ca.crt", []byte(caCert), 0755); err != nil {
		t.Fatal(err)
	}

	config := Config{
		Tokenfile:              tmpdir + "/token.txt",
		Address:                server.URL,
		Role:                   "client",
		Name:                   "edge0.edgefarm.io",
		ServerCA:               tmpdir + "/server-ca.crt",
		PKI:                    PKI,
		OutCAfile:              tmpdir + "/ca.crt",
		OutCertfile:            tmpdir + "/client.crt",
		OutKeyfile:             tmpdir + "/client.key",
		ValidityCheckTolerance: 80,
	}

	cr, err := New(config)
	if err != nil {
		t.Fatalf("Failed to create cert retrieval: %v", err)
	}

	for i := 0; i < 3; i++ {

		if err := cr.Retrieve(); err != nil {
			t.Fatalf("Failed to retrieve: %v", err)
		}
	}
	if expected := 1; expected != invocations {
		t.Errorf("Wrong number of retrievals, expected %d but got %d", expected, invocations)
	}

}

func TestCommaSeperatedToStringList(t *testing.T) {
	assert := assert.New(t)

	list := CommaSeperatedToStringList("a,b,c")
	assert.Equal(3, len(list))
	assert.Equal("a", list[0])
	assert.Equal("b", list[1])
	assert.Equal("c", list[2])
}
