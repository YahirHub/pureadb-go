package adb

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"time"
)

const adbRSAPublicKeySize = 524

type Key struct {
	Private *rsa.PrivateKey
	Name    string
}

func GenerateKey(name string) (*Key, error) {
	if name == "" {
		name = "pureadb@go"
	}
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return &Key{Private: k, Name: name}, nil
}

func ParsePrivateKeyPEM(data []byte, name string) (*Key, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("adb: invalid PEM private key")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return &Key{Private: key, Name: defaultKeyName(name)}, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("adb: private key is not RSA")
	}
	return &Key{Private: key, Name: defaultKeyName(name)}, nil
}

func defaultKeyName(name string) string {
	if name == "" {
		return "pureadb@go"
	}
	return name
}

func (k *Key) MarshalPrivateKeyPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k.Private)})
}

func (k *Key) PublicKeyADB() (string, error) {
	blob, err := k.androidRSAPublicKey()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(blob) + " " + defaultKeyName(k.Name), nil
}

func (k *Key) SignADBToken(token []byte) ([]byte, error) {
	if len(token) != sha1.Size {
		return nil, errors.New("adb: AUTH token must be a SHA-1-sized digest")
	}
	return rsa.SignPKCS1v15(rand.Reader, k.Private, crypto.SHA1, token)
}

func (k *Key) tlsCertificate() (tls.Certificate, error) {
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Country: []string{"US"}, Organization: []string{"Android"}, CommonName: "Adb"},
		Issuer:                pkix.Name{Country: []string{"US"}, Organization: []string{"Android"}, CommonName: "Adb"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.Private.PublicKey, k.Private)
	if err != nil {
		return tls.Certificate{}, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k.Private, Leaf: cert}, nil
}

func (k *Key) androidRSAPublicKey() ([]byte, error) {
	if k == nil || k.Private == nil || k.Private.N == nil {
		return nil, errors.New("adb: nil RSA key")
	}
	if k.Private.N.BitLen() > 2048 {
		return nil, errors.New("adb: only RSA-2048 keys are supported")
	}

	out := make([]byte, adbRSAPublicKeySize)
	putLE32(out[0:4], 64)

	modLE := fixedLittleEndian(k.Private.N, 256)
	n0 := uint64(readLE32(modLE[:4]))
	modulus := new(big.Int).Lsh(big.NewInt(1), 32)
	inv := new(big.Int).ModInverse(new(big.Int).SetUint64(n0), modulus)
	if inv == nil {
		return nil, errors.New("adb: RSA modulus has no inverse modulo 2^32")
	}
	n0inv := uint32(0 - uint32(inv.Uint64()))
	putLE32(out[4:8], n0inv)
	copy(out[8:264], modLE)

	// rr = R^2 mod N, where R = 2^2048.
	rr := new(big.Int).Exp(big.NewInt(2), big.NewInt(4096), k.Private.N)
	copy(out[264:520], fixedLittleEndian(rr, 256))
	putLE32(out[520:524], uint32(k.Private.E))
	return out, nil
}

func fixedLittleEndian(n *big.Int, size int) []byte {
	be := n.Bytes()
	out := make([]byte, size)
	for i := 0; i < len(be) && i < size; i++ {
		out[i] = be[len(be)-1-i]
	}
	return out
}
