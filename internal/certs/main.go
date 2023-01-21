package certs

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

type Client struct {
	CommonName string
	CrtKeyPair
}

type CrtKeyPair struct {
	Crt *x509.Certificate
	Key any
}

var prefix string

func Init(path string) {
	prefix = path
}

func getPemBlockBytes(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	b, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(b)

	return block.Bytes, nil
}

func getFileDataByPath(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return io.ReadAll(f)
}

func getKeyPathByName(name string) string {
	return filepath.Join(prefix, "private", fmt.Sprintf("%s.key", name))
}

func getCsrPathByName(name string) string {
	return filepath.Join(prefix, "reqs", fmt.Sprintf("%s.csr", name))
}

func getCrtPathByName(name string) string {
	return filepath.Join(prefix, "issued", fmt.Sprintf("%s.crt", name))
}

func getCrlPath() string {
	return filepath.Join(prefix, "crl.pem")
}

func getKeyByName(name string) (any, error) {
	b, err := getPemBlockBytes(getKeyPathByName(name))
	if err != nil {
		return nil, err
	}

	return x509.ParsePKCS8PrivateKey(b)
}

func GetKeyBytesByName(name string) ([]byte, error) {
	return getPemBlockBytes(getKeyPathByName(name))
}

func getCsrByPath(path string) (*x509.CertificateRequest, error) {
	b, err := getPemBlockBytes(path)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificateRequest(b)
}

func getCrtByPath(path string) (*x509.Certificate, error) {
	b, err := getPemBlockBytes(path)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(b)
}

func getCaCrt() (*x509.Certificate, error) {
	path := filepath.Join(prefix, "ca.crt")

	return getCrtByPath(path)
}

func getCrl() (*x509.RevocationList, error) {
	b, err := getPemBlockBytes(getCrlPath())
	if err != nil {
		return nil, err
	}

	return x509.ParseRevocationList(b)
}

func GetCaCrtData() ([]byte, error) {
	path := filepath.Join(prefix, "ca.crt")

	return getFileDataByPath(path)
}

func GetKeyDataByName(name string) ([]byte, error) {
	return getFileDataByPath(getKeyPathByName(name))
}

func GetCrtDataByName(name string) ([]byte, error) {
	return getFileDataByPath(getCrtPathByName(name))
}

func GetTLSAuth() ([]byte, error) {
	f, err := os.Open(filepath.Join(prefix, "ta.key"))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return io.ReadAll(f)
}

func getCrtByName(name string) (*x509.Certificate, error) {
	return getCrtByPath(getCrtPathByName(name))
}

func GetClient(name string) (*Client, error) {
	key, err := getKeyByName(name)
	if err != nil {
		return nil, err
	}

	crt, err := getCrtByName(name)
	if err != nil {
		return nil, err
	}

	return &Client{
		CommonName: crt.Subject.CommonName,
		CrtKeyPair: CrtKeyPair{
			Crt: crt,
			Key: key,
		},
	}, nil
}

func genKeyByName(name string) error {
	// key, err := rsa.GenerateKey(rand.Reader, 4096)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM := new(bytes.Buffer)
	if err := pem.Encode(keyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	}); err != nil {
		return err
	}
	f, err := os.OpenFile(getKeyPathByName(name), os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return err
	}

	_, err = f.Write(keyPEM.Bytes())
	return err
}

func genCsrByName(name string) error {
	key, err := getKeyByName(name)
	if err != nil {
		return fmt.Errorf("getting private key failed: %w", err)
	}

	csr := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: name,
		},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, csr, key)
	if err != nil {
		return fmt.Errorf("failed to create certificate request: %w", err)
	}
	csrPEM := new(bytes.Buffer)
	err = pem.Encode(csrPEM, &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	})
	if err != nil {
		return fmt.Errorf("failed to encode client certificate request pem block: %w", err)
	}
	f, err := os.OpenFile(getCsrPathByName(name), os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return fmt.Errorf("failed to open new certificate request file: %w", err)
	}

	_, err = f.Write(csrPEM.Bytes())
	return err
}

func genCrtByName(name string) error {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return err
	}

	caCrt, err := getCaCrt()
	if err != nil {
		return fmt.Errorf("getting CA certificate failed: %w", err)
	}

	csr, err := getCsrByPath(getCsrPathByName(name))
	if err != nil {
		return fmt.Errorf("getting certificate request failed: %w", err)
	}
	key, ok := (csr.PublicKey).(*rsa.PublicKey)
	if !ok {
		return errors.New("failed private key type assertion")
	}
	keyHash := sha1.Sum(
		x509.MarshalPKCS1PublicKey(key),
	)

	crt := &x509.Certificate{
		Signature:          csr.Signature,
		SignatureAlgorithm: csr.SignatureAlgorithm,

		PublicKey:          csr.PublicKey,
		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,

		SerialNumber: serialNumber,
		Issuer:       caCrt.Subject,
		Subject: pkix.Name{
			CommonName: name,
		},
		SubjectKeyId:   keyHash[:],
		AuthorityKeyId: keyHash[:],

		NotBefore: time.Now(),
		// should be parameterized
		NotAfter: time.Now().Add(24 * time.Hour),

		BasicConstraintsValid: true,
		IsCA:                  false,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	caKey, err := getKeyByName("ca")
	if err != nil {
		return fmt.Errorf("getting CA private key failed: %w", err)
	}
	crtBytes, err := x509.CreateCertificate(rand.Reader, crt, caCrt, csr.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("generating client certificate failed: %w", err)
	}
	crtPEM := new(bytes.Buffer)
	err = pem.Encode(crtPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: crtBytes,
	})
	if err != nil {
		return fmt.Errorf("failed to encode client certificate pem block: %w", err)
	}
	f, err := os.OpenFile(getCrtPathByName(name), os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return fmt.Errorf("failed to open new certificate file: %w", err)
	}

	_, err = f.Write(crtPEM.Bytes())
	return err
}

func GenClient(name string) error {
	_, err := GetClient(name)
	if err != nil {
		if err := genKeyByName(name); err != nil {
			return err
		}
		if err := genCsrByName(name); err != nil {
			return err
		}
		if err := genCrtByName(name); err != nil {
			return err
		}
	}

	return nil
}

func RevokeClient(name string) error {
	crl, err := getCrl()
	if err != nil {
		return fmt.Errorf("failed to get certificate revocation list: %w", err)
	}
	if crl.Number == nil {
		crl.Number = big.NewInt(0)
	}

	crt, err := getCrtByName(name)
	if err != nil {
		return fmt.Errorf("failed to get client certificate: %w", err)
	}
	crl.RevokedCertificates = append(
		crl.RevokedCertificates,
		pkix.RevokedCertificate{
			SerialNumber:   crt.SerialNumber,
			RevocationTime: time.Now(),
		},
	)

	caCrt, err := getCaCrt()
	if err != nil {
		return fmt.Errorf("getting CA certificate failed: %w", err)
	}

	caKeyAsAny, err := getKeyByName("ca")
	if err != nil {
		return fmt.Errorf("getting CA private key failed: %w", err)
	}
	caKey, ok := caKeyAsAny.(*rsa.PrivateKey)
	if !ok {
		return errors.New("failed private key type assertion")
	}

	crlBytes, err := x509.CreateRevocationList(rand.Reader, crl, caCrt, caKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate revocation list: %w", err)
	}

	crlPEM := new(bytes.Buffer)
	err = pem.Encode(crlPEM, &pem.Block{
		Type:  "X509 CRL",
		Bytes: crlBytes,
	})
	if err != nil {
		return fmt.Errorf("failed to encode certificate revocation list pem block: %w", err)
	}
	f, err := os.OpenFile(getCrlPath(), os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return fmt.Errorf("failed to open certificate revocation list file: %w", err)
	}

	if _, err := f.Write(crlPEM.Bytes()); err != nil {
		return fmt.Errorf("failed to write certificate revocation list: %w", err)
	}

	// rename files
	path := filepath.Join(prefix, "revoked/certs_by_serial", fmt.Sprintf("%s.crt", crt.SerialNumber))
	if err := os.Rename(getCrtPathByName(name), path); err != nil {
		return fmt.Errorf("failed to rename client certificate: %w", err)
	}

	path = filepath.Join(prefix, "revoked/private_by_serial", fmt.Sprintf("%s.key", crt.SerialNumber))
	if err := os.Rename(getKeyPathByName(name), path); err != nil {
		return fmt.Errorf("failed to rename client certificate key: %w", err)
	}

	path = filepath.Join(prefix, "revoked/reqs_by_serial", fmt.Sprintf("%s.req", crt.SerialNumber))
	if err := os.Rename(getCsrPathByName(name), path); err != nil {
		return fmt.Errorf("failed to rename client certificate request: %w", err)
	}

	return nil
}
