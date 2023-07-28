package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"os"
	"time"
)

func main() {

	// --- ROOT CERTIFICATE ---
	rootPrivateKeyByte, err := ioutil.ReadFile("keys/privatekey.pem")
	if err != nil {
		panic("failed to load root private key " + err.Error())
	}
	//decode() will find the nex pem formatted block in the input and return a pem block structure which contains
	//three fields Type,Headers,Bytes. the bytes field contains the actual decoded data -- check encoding/pem website --
	block, _ := pem.Decode(rootPrivateKeyByte)
	pppp, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	rootPrivate := pppp.(ed25519.PrivateKey)
	rootPublicKey := rootPrivate.Public()

	// create the root CA certificate template.
	rootCATemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1028),
		Subject: pkix.Name{
			CommonName:   "exampleCA",
			Organization: []string{"Company, INC."},
			Country:      []string{"US"},
			Province:     []string{""},
			Locality:     []string{"San Francisco"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), //valid for 10 years
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	rootCATemplate.DNSNames = append(rootCATemplate.DNSNames, "localhost")
	//create the root certificate - self signed
	rootCaCert, err := x509.CreateCertificate(rand.Reader, rootCATemplate, rootCATemplate, rootPublicKey, rootPrivate)

	if err != nil {
		panic("failed to create Root CA Certificate " + err.Error())
	}
	outputRootCert, err := os.Create("root.pem")
	if err != nil {
		panic("failed to create Root CA certificate file " + err.Error())
	}

	pem.Encode(outputRootCert, &pem.Block{Type: "CERTIFICATE", Bytes: rootCaCert})
	outputRootCert.Close()

	// --- INTERMEDIATE CERTIFICATE ---
	intermediatePrivateKey, err := ioutil.ReadFile("keys/interPrivateKey.pem")
	if err != nil {
		panic("failed to load intermediate private key " + err.Error())
	}
	block2, _ := pem.Decode(intermediatePrivateKey)
	pppp2, err := x509.ParsePKCS8PrivateKey(block2.Bytes)
	interPrivate := pppp2.(ed25519.PrivateKey)
	interPublic := interPrivate.Public()
	// interPrivateKey := ed25519.NewKeyFromSeed(interPrivate.Seed())

	// create the Intermediate certificate template.
	intermediateTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1028),
		Subject: pkix.Name{
			Organization: []string{"Intermediate"},
			Country:      []string{"US"},
			Province:     []string{""},
			Locality:     []string{"Los Angelos"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(3, 0, 0), //valid for 10 years
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	intermediateCACert, err := x509.CreateCertificate(rand.Reader, intermediateTemplate, rootCATemplate, interPublic, interPrivate)
	if err != nil {
		panic("failed to create Root CA Certificate " + err.Error())
	}

	outputIntermediateCert, err := os.Create("intermediate.pem")
	if err != nil {
		panic("failed to create Root CA certificate file " + err.Error())
	}

	pem.Encode(outputIntermediateCert, &pem.Block{Type: "CERTIFICATE", Bytes: intermediateCACert})
	outputIntermediateCert.Close()

	// --- CLIENT CERTIFICATE ---
	clientPrivateKeyByte, err := ioutil.ReadFile("keys/clientPrivateKey.pem")
	if err != nil {
		panic("failed to load client private key " + err.Error())
	}
	block3, _ := pem.Decode(clientPrivateKeyByte)
	pppp3, err := x509.ParsePKCS8PrivateKey(block3.Bytes)
	clientPriv := pppp3.(ed25519.PrivateKey)
	clientPublic := clientPriv.Public()
	// clientPrivateKey := ed25519.NewKeyFromSeed(clientPriv.Seed())

	//create the client certificate template
	clientCertTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1028),
		Subject: pkix.Name{
			CommonName:   "localhost",
			Organization: []string{"client"},
			Country:      []string{"Uk"},
			Province:     []string{""},
			Locality:     []string{"London"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0), //valid for 1 years
		IsCA:                  false,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	clientCertTemplate.DNSNames = append(clientCertTemplate.DNSNames, "localhost")
	clientCert, err := x509.CreateCertificate(rand.Reader, clientCertTemplate, intermediateTemplate, clientPublic, clientPriv)
	if err != nil {
		panic("Failed to create client certificate, " + err.Error())
	}
	outputClientCert, err := os.Create("client.pem")
	if err != nil {
		panic("failed to create Root CA certificate file " + err.Error())
	}

	pem.Encode(outputClientCert, &pem.Block{Type: "CERTIFICATE", Bytes: clientCert})
	outputClientCert.Close()

	// --- SERVER CERTIFICATE ---
	serverPrivateKeyByte, err := ioutil.ReadFile("keys/serverPrivateKey.pem")
	if err != nil {
		panic("failed to load server private key " + err.Error())
	}
	block4, _ := pem.Decode(serverPrivateKeyByte)
	pppp4, err := x509.ParsePKCS8PrivateKey(block4.Bytes)
	serverPriv := pppp4.(ed25519.PrivateKey)
	// serverPriv := ed25519.PrivateKey(serverPrivateKeyByte)
	serverPublicKey := serverPriv.Public()
	// serverPrivateKey := ed25519.NewKeyFromSeed(serverPriv.Seed())

	//create server certificate template
	serverCertTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1028),
		Subject: pkix.Name{
			CommonName:   "localhost",
			Organization: []string{"server"},
			Country:      []string{"US"},
			Province:     []string{""},
			Locality:     []string{"Los Angelos"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0), //valid for 1 years
		IsCA:                  false,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	serverCertTemplate.DNSNames = append(serverCertTemplate.DNSNames, "localhost")
	serverCertificate, err := x509.CreateCertificate(rand.Reader, serverCertTemplate, intermediateTemplate, serverPublicKey, serverPriv)

	if err != nil {
		panic("failed to create server certificate")
	}
	outputServerCert, err := os.Create("server.pem")
	if err != nil {
		panic("failed to create server certificate file " + err.Error())
	}

	pem.Encode(outputServerCert, &pem.Block{Type: "CERTIFICATE", Bytes: serverCertificate})
	outputClientCert.Close()

}
