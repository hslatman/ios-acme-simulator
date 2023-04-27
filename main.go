package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/mholt/acmez"
	"github.com/mholt/acmez/acme"
	"github.com/smallstep/certinfo"
	"go.step.sm/crypto/minica"
	"go.step.sm/crypto/pemutil"
	"go.step.sm/crypto/x509util"
)

var (
	// acme settings
	directory        string
	clientIdentifier string
	udid             string
	serial           string

	// attestation CA settings
	rootCert                string
	intermediateCert        string
	intermediateKey         string
	intermediateKeyPassword string
)

func main() {
	flag.StringVar(&directory, "directory", "", "The URL of the ACME directory")
	flag.StringVar(&clientIdentifier, "client-identifier", "", `The "ClientIdentifier" to use in the ACME request`)
	flag.StringVar(&udid, "udid", "device.id1", `The (fake) Apple UDID`)
	flag.StringVar(&serial, "serial", "12345", `The (fake) Apple serial number`)
	flag.StringVar(&rootCert, "root", "", "Path to the root CA certificate in PEM format")
	flag.StringVar(&intermediateCert, "intermediate", "", "Path to the intermediate CA certificate in PEM format")
	flag.StringVar(&intermediateKey, "key", "", "Path to the intermediate CA private key")
	flag.StringVar(&intermediateKeyPassword, "pass", "", "Password for the intermediate CA private key")

	flag.Parse()

	err := run()
	if err != nil {
		log.Fatal(err)
	}
}

func run() error {

	if directory == "" {
		return errors.New("-directory required")
	}
	if clientIdentifier == "" {
		return errors.New("-client-identifier required")
	}
	if rootCert == "" {
		return errors.New("-root required")
	}
	if intermediateCert == "" {
		return errors.New("-intermediate required")
	}
	if intermediateKey == "" {
		return errors.New("-key required")
	}

	// Before you can get a cert, you'll need an account registered with
	// the ACME CA; it needs a private key which should obviously be
	// different from any key used for certificates!
	accountPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generating account key: %w", err)
	}
	account := acme.Account{
		Contact:              []string{"mailto:someone@example.com"},
		TermsOfServiceAgreed: true,
		PrivateKey:           accountPrivateKey,
	}

	root, err := pemutil.ReadCertificate(rootCert)
	if err != nil {
		return err
	}

	intermediate, err := pemutil.ReadCertificate(intermediateCert)
	if err != nil {
		return err
	}

	anySigner, err := pemutil.Read(intermediateKey, pemutil.WithPassword([]byte(intermediateKeyPassword)))
	if err != nil {
		return err
	}

	signer, ok := anySigner.(crypto.Signer)
	if !ok {
		return fmt.Errorf("key read from %q is not a signer", intermediateKey)
	}

	// create a fake attestation CA, backed by `minica`
	attestationCA := &minica.CA{
		Root:         root,
		Intermediate: intermediate,
		Signer:       signer,
	}

	// Every certificate needs a key. The attestation solver requires it too,
	// because the (fake) attestation CA needs to sign an attestation certificate
	// for the same key as in the final ACME CSR.
	certPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed generating certificate key: %w", err)
	}

	deviceAttestSolver := &attSolver{account, attestationCA, certPrivateKey}

	client := acmez.Client{
		Client: &acme.Client{
			Directory: directory,
			HTTPClient: &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true, // just tinkering locally
					},
				},
			},
		},
		ChallengeSolvers: map[string]acmez.Solver{
			acme.ChallengeTypeDeviceAttest01: deviceAttestSolver,
		},
	}

	// If the account is new, we need to create it; only do this once!
	// then be sure to securely store the account key and metadata so
	// you can reuse it later!
	ctx := context.Background()
	account, err = client.NewAccount(ctx, account)
	if err != nil {
		return fmt.Errorf("failed creating new account: %w", err)
	}

	// prepare the SANs for the CSR. Currently only one PermanentIdentifier
	// is supported. The PermanentIdentifier (currently) is required to have
	// the value of the ClientIdentifier in `step-ca`.
	sans := []x509util.SubjectAlternativeName{}
	permanentIdentifiers := []string{clientIdentifier}
	for _, pi := range permanentIdentifiers {
		sans = append(sans, x509util.SubjectAlternativeName{
			Type:  x509util.PermanentIdentifierType,
			Value: pi,
		})
	}
	ext, err := createSubjectAltNameExtension(nil, nil, nil, nil, sans, true)
	if err != nil {
		return err
	}
	template := &x509.CertificateRequest{
		ExtraExtensions: []pkix.Extension{
			{
				Id:       asn1.ObjectIdentifier(ext.ID),
				Critical: ext.Critical,
				Value:    ext.Value,
			},
		},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, certPrivateKey)
	if err != nil {
		return err
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return err
	}

	// Once your client, account, and certificate key are all ready,
	// it's time to request a certificate!
	certs, err := client.ObtainCertificateUsingCSR(ctx, account, csr)
	if err != nil {
		return fmt.Errorf("failed obtaining certificate: %w", err)
	}
	if len(certs) == 0 {
		return errors.New("no certificates")
	}

	// ACME servers should usually give you the entire certificate chain
	// in PEM format, and sometimes even alternate chains! It's up to you
	// which one(s) to store and use, but whatever you do, be sure to
	// store the certificate and key somewhere safe and secure, i.e. don't
	// lose them!
	cert := certs[0]
	log.Printf("[DEBUG] Certificate %q:\n%s\n\n", cert.URL, cert.ChainPEM)
	chain, err := pemutil.ParseCertificateBundle(cert.ChainPEM)
	if err != nil {
		return fmt.Errorf("failed parsing certificate bundle: %w", err)
	}
	for _, c := range chain {
		s, err := certinfo.CertificateText(c)
		if err != nil {
			return fmt.Errorf("failed getting certificate text: %w", err)
		}
		fmt.Println(s)
	}
	os.WriteFile("certs.pem", cert.ChainPEM, 0644)

	// just for demo purpose, try renewing
	time.Sleep(3 * time.Second)
	log.Printf("[DEBUG] renewing ...")

	certs, err = client.ObtainCertificateUsingCSR(ctx, account, csr)
	if err != nil {
		return fmt.Errorf("failed obtaining certificate: %w", err)
	}
	if len(certs) == 0 {
		return errors.New("no certificates on renew")
	}

	cert = certs[0]
	log.Printf("[DEBUG] Certificate %q:\n%s\n\n", cert.URL, cert.ChainPEM)
	chain, err = pemutil.ParseCertificateBundle(cert.ChainPEM)
	if err != nil {
		return fmt.Errorf("failed parsing certificate bundle: %w", err)
	}
	for _, c := range chain {
		s, err := certinfo.CertificateText(c)
		if err != nil {
			return fmt.Errorf("failed getting certificate text: %w", err)
		}
		fmt.Println(s)
	}
	os.WriteFile("certs-renew.pem", cert.ChainPEM, 0644)

	return nil
}

// attSolver is a acmez.Solver that mimics the Apple attestation flow, backed
// by a fake Attestation CA under the users control. The CA should be configured
// to allow the `apple` format and have the attestation root CA controlled by the
// user configured as `attestationRoots`.
type attSolver struct {
	account       acme.Account
	attestationCA *minica.CA
	csrSigner     crypto.Signer
}

func (s *attSolver) Present(ctx context.Context, chal acme.Challenge) error {
	log.Printf("[DEBUG] present: %#v", chal)
	return nil
}

func (s *attSolver) CleanUp(ctx context.Context, chal acme.Challenge) error {
	log.Printf("[DEBUG] cleanup: %#v", chal)
	return nil
}

type attestationObject struct {
	Format       string                 `json:"fmt"`
	AttStatement map[string]interface{} `json:"attStmt,omitempty"`
}

var (
	oidAppleSerialNumber                    = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 9, 1}
	oidAppleUniqueDeviceIdentifier          = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 9, 2}
	oidAppleSecureEnclaveProcessorOSVersion = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 10, 2}
	oidAppleNonce                           = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 11, 1}
)

func (s *attSolver) Payload(ctx context.Context, chal acme.Challenge) (interface{}, error) {
	log.Printf("[DEBUG] payload: %#v", chal)

	nonceSum := sha256.Sum256([]byte(chal.Token)) // the nonce is just the SHA256 of the challenge token
	template := &x509.Certificate{
		Subject:   pkix.Name{CommonName: "fake attestation cert"},
		PublicKey: s.csrSigner.Public(), // attestation leaf must have same public key fingerprint as CSR
		ExtraExtensions: []pkix.Extension{
			{
				Id:       oidAppleSerialNumber,
				Value:    []byte(serial),
				Critical: false,
			},
			{
				Id:       oidAppleUniqueDeviceIdentifier,
				Value:    []byte(udid),
				Critical: false,
			},
			{
				Id:       oidAppleSecureEnclaveProcessorOSVersion,
				Value:    []byte("16.0"),
				Critical: false,
			},
			{
				Id:       oidAppleNonce,
				Value:    nonceSum[:],
				Critical: false,
			},
		},
	}
	cert, err := s.attestationCA.Sign(template)
	if err != nil {
		return nil, err
	}

	chain := []*x509.Certificate{cert, s.attestationCA.Intermediate}
	chainBytes := make([][]byte, len(chain))
	for i, cert := range chain {
		chainBytes[i] = cert.Raw
	}

	attObj := &attestationObject{
		Format: "apple",
		AttStatement: map[string]interface{}{
			"x5c": chainBytes,
		},
	}
	b, err := cbor.Marshal(attObj)
	if err != nil {
		return nil, err
	}

	attObjString := base64.RawURLEncoding.EncodeToString(b)

	return map[string]string{
		"attObj": attObjString,
	}, nil
}

var (
	oidSubjectAlternativeName = asn1.ObjectIdentifier{2, 5, 29, 17}
)

// createSubjectAltNameExtension will construct an Extension containing all
// SubjectAlternativeNames held in a Certificate. It implements more types than
// the golang x509 library, so it is used whenever OtherName or RegisteredID
// type SANs are present in the certificate.
//
// See also https://datatracker.ietf.org/doc/html/rfc5280.html#section-4.2.1.6
//
// TODO(hs): this was copied from go.step.sm/crypto/x509util to make it easier
// to create the SAN extension for testing purposes. Should it be exposed instead?
func createSubjectAltNameExtension(dnsNames, emailAddresses x509util.MultiString, ipAddresses x509util.MultiIP, uris x509util.MultiURL, sans []x509util.SubjectAlternativeName, subjectIsEmpty bool) (x509util.Extension, error) {
	var zero x509util.Extension

	var rawValues []asn1.RawValue
	for _, dnsName := range dnsNames {
		rawValue, err := x509util.SubjectAlternativeName{
			Type: x509util.DNSType, Value: dnsName,
		}.RawValue()
		if err != nil {
			return zero, err
		}

		rawValues = append(rawValues, rawValue)
	}

	for _, emailAddress := range emailAddresses {
		rawValue, err := x509util.SubjectAlternativeName{
			Type: x509util.EmailType, Value: emailAddress,
		}.RawValue()
		if err != nil {
			return zero, err
		}

		rawValues = append(rawValues, rawValue)
	}

	for _, ip := range ipAddresses {
		rawValue, err := x509util.SubjectAlternativeName{
			Type: x509util.IPType, Value: ip.String(),
		}.RawValue()
		if err != nil {
			return zero, err
		}

		rawValues = append(rawValues, rawValue)
	}

	for _, uri := range uris {
		rawValue, err := x509util.SubjectAlternativeName{
			Type: x509util.URIType, Value: uri.String(),
		}.RawValue()
		if err != nil {
			return zero, err
		}

		rawValues = append(rawValues, rawValue)
	}

	for _, san := range sans {
		rawValue, err := san.RawValue()
		if err != nil {
			return zero, err
		}

		rawValues = append(rawValues, rawValue)
	}

	// Now marshal the rawValues into the ASN1 sequence, and create an Extension object to hold the extension
	rawBytes, err := asn1.Marshal(rawValues)
	if err != nil {
		return zero, fmt.Errorf("error marshaling SubjectAlternativeName extension to ASN1: %w", err)
	}

	return x509util.Extension{
		ID:       x509util.ObjectIdentifier(oidSubjectAlternativeName),
		Critical: subjectIsEmpty,
		Value:    rawBytes,
	}, nil
}
