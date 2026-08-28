// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	cpb "github.com/openconfig/attestz/proto/common_definitions"
	"github.com/openconfig/attestz/service/biz"
)

type caCert struct {
	certX509 *x509.Certificate
	certPem  string
	privKey  any
}

func generateCaCert(t *testing.T) *caCert {
	t.Helper()
	certSerial, err := rand.Int(rand.Reader, big.NewInt(100000))
	if err != nil {
		t.Fatalf("failed to generate rand int for cert serial: %v", err)
	}
	certX509 := &x509.Certificate{
		SerialNumber:          certSerial,
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate a ECC P384 priv key for CA cert: %v", err)
	}

	certDer, err := x509.CreateCertificate(rand.Reader, certX509, certX509, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("failed to create x509 self-signed CA cert: %v", err)
	}

	certPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certDer,
		})

	return &caCert{
		certX509: certX509,
		certPem:  string(certPem),
		privKey:  privKey,
	}
}

func generateInterCaCert(t *testing.T, issuerCert *x509.Certificate, issuerPrivKey any) *caCert {
	t.Helper()
	certSerial, err := rand.Int(rand.Reader, big.NewInt(100000))
	if err != nil {
		t.Fatalf("failed to generate rand int for cert serial: %v", err)
	}
	certX509 := &x509.Certificate{
		SerialNumber:          certSerial,
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate a ECC P384 priv key for CA cert: %v", err)
	}

	certDer, err := x509.CreateCertificate(rand.Reader, certX509, issuerCert, &privKey.PublicKey, issuerPrivKey)
	if err != nil {
		t.Fatalf("failed to create x509 intermediate CA cert: %v", err)
	}

	certPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certDer,
		})

	parsedCert, err := x509.ParseCertificate(certDer)
	if err != nil {
		t.Fatalf("failed to parse generated intermediate CA cert: %v", err)
	}

	return &caCert{
		certX509: parsedCert,
		certPem:  string(certPem),
		privKey:  privKey,
	}
}

type signedTpmCert struct {
	certPem   string
	pubKeyPem string
}

type asymAlgo int

const (
	rsa4096Algo asymAlgo = iota
	rsa2048Algo
	rsa1024Algo
	eccP521Algo
	eccP384Algo
	eccP256Algo
	eccP224Algo
	ed25519Algo
)

type certCreationParams struct {
	asymAlgo          asymAlgo
	certSubjectSerial string
	signingCert       *x509.Certificate
	signingPrivKey    any
	notBefore         time.Time
	notAfter          time.Time
}

func generateSignedCert(t *testing.T, params *certCreationParams) *signedTpmCert {
	t.Helper()
	certSerial, err := rand.Int(rand.Reader, big.NewInt(100000))
	if err != nil {
		t.Fatalf("failed to generate rand int for cert serial: %v", err)
	}
	cert := &x509.Certificate{
		SerialNumber: certSerial,
		Subject: pkix.Name{
			SerialNumber: params.certSubjectSerial,
		},
		NotBefore: params.notBefore,
		NotAfter:  params.notAfter,
	}

	var certPubKey any
	switch params.asymAlgo {
	case rsa4096Algo:
		certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
		if err == nil {
			certPubKey = &certPrivKey.PublicKey
		}
	case rsa2048Algo:
		certPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err == nil {
			certPubKey = &certPrivKey.PublicKey
		}
	case rsa1024Algo:
		certPrivKey, err := rsa.GenerateKey(rand.Reader, 1024)
		if err == nil {
			certPubKey = &certPrivKey.PublicKey
		}
	case eccP224Algo:
		certPrivKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
		if err == nil {
			certPubKey = &certPrivKey.PublicKey
		}
	case eccP256Algo:
		certPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err == nil {
			certPubKey = &certPrivKey.PublicKey
		}
	case eccP384Algo:
		certPrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err == nil {
			certPubKey = &certPrivKey.PublicKey
		}
	case eccP521Algo:
		certPrivKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err == nil {
			certPubKey = &certPrivKey.PublicKey
		}
	case ed25519Algo:
		certPubKey, _, err = ed25519.GenerateKey(rand.Reader)
	default:
		t.Fatalf("unrecognized asymmetric algo: %d", params.asymAlgo)
	}
	if err != nil {
		t.Fatalf("failed to generate asym key pair from asymmetric algo %d: %v", params.asymAlgo, err)
	}

	certDer, err := x509.CreateCertificate(rand.Reader, cert, params.signingCert, certPubKey, params.signingPrivKey)
	if err != nil {
		t.Fatalf("failed to create a signed x509 cert: %v", err)
	}
	certPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certDer,
		})

	derPub, err := x509.MarshalPKIXPublicKey(certPubKey)
	if err != nil {
		t.Fatalf("failed to marshal pub key to DER: %v", err)
	}
	pubKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: derPub,
		})

	return &signedTpmCert{
		certPem:   string(certPem),
		pubKeyPem: string(pubKeyPem),
	}
}

func TestVerifyIakAndIDevIDCertsSansSN(t *testing.T) {
	unknownCaCert := generateCaCert(t)

	cardID := &cpb.ControlCardVendorId{
		ControlCardRole:     cpb.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE,
		ControlCardSerial:   "CARD-SERIAL-1234",
		ChassisSerialNumber: "CHASSIS-SERIAL-5678",
	}

	tests := []struct {
		desc                    string
		wantError               bool
		cardID                  *cpb.ControlCardVendorId
		iakCertAsymAlgo         asymAlgo
		iakCertSubjectSerial    string
		iakCertNotBefore        time.Time
		iakCertNotAfter         time.Time
		iDevIDCertAsymAlgo      asymAlgo
		iDevIDCertSubjectSerial string
		iDevIDCertNotBefore     time.Time
		iDevIDCertNotAfter      time.Time
		customIakCertPem        string
		customIDevIDCertPem     string
		customIakCaRootPem      string
		customIDevIDCaRootPem   string
		noIDevID                bool
		nilReq                  bool
	}{
		{
			desc:                    "Success: Mismatched serial numbers (IAK, IDevID, and cardID all differ)",
			wantError:               false,
			cardID:                  cardID,
			iakCertAsymAlgo:         rsa4096Algo,
			iakCertSubjectSerial:    "DIFFERENT-IAK-SERIAL",
			iakCertNotBefore:        time.Now().Add(-1 * time.Hour),
			iakCertNotAfter:         time.Now().AddDate(0, 0, 10),
			iDevIDCertAsymAlgo:      eccP384Algo,
			iDevIDCertSubjectSerial: "ANOTHER-IDEVID-SERIAL",
			iDevIDCertNotBefore:     time.Now().Add(-1 * time.Hour),
			iDevIDCertNotAfter:      time.Now().AddDate(1, 0, 0),
		},
		{
			desc:                 "Success: ECC P521 IAK and no IDevID cert with mismatched serial",
			wantError:            false,
			cardID:               cardID,
			iakCertAsymAlgo:      eccP521Algo,
			iakCertSubjectSerial: "NON-MATCHING-SERIAL",
			iakCertNotBefore:     time.Now().Add(-1 * time.Hour),
			iakCertNotAfter:      time.Now().AddDate(0, 1, 0),
			noIDevID:             true,
		},
		{
			desc:                    "Success: ECC P256 IAK and IDevID certs with empty serial numbers",
			wantError:               false,
			cardID:                  cardID,
			iakCertAsymAlgo:         eccP256Algo,
			iakCertSubjectSerial:    "",
			iakCertNotBefore:        time.Now().Add(-1 * time.Hour),
			iakCertNotAfter:         time.Now().AddDate(0, 1, 0),
			iDevIDCertAsymAlgo:      eccP256Algo,
			iDevIDCertSubjectSerial: "",
			iDevIDCertNotBefore:     time.Now().Add(-1 * time.Hour),
			iDevIDCertNotAfter:      time.Now().AddDate(0, 0, 10),
		},
		{
			desc:                    "Success: RSA 2048 IDevID and ECC P384 IAK",
			wantError:               false,
			cardID:                  cardID,
			iakCertAsymAlgo:         eccP384Algo,
			iakCertSubjectSerial:    "SOME-SERIAL",
			iakCertNotBefore:        time.Now().Add(-1 * time.Hour),
			iakCertNotAfter:         time.Now().AddDate(0, 1, 0),
			iDevIDCertAsymAlgo:      rsa2048Algo,
			iDevIDCertSubjectSerial: "SOME-OTHER-SERIAL",
			iDevIDCertNotBefore:     time.Now().Add(-1 * time.Hour),
			iDevIDCertNotAfter:      time.Now().AddDate(0, 1, 0),
		},
		{
			desc:      "Failure: Nil request",
			wantError: true,
			nilReq:    true,
		},
		{
			desc:                    "Failure: unsupported ED25519 algo for IAK",
			wantError:               true,
			cardID:                  cardID,
			iakCertAsymAlgo:         ed25519Algo,
			iakCertSubjectSerial:    "SERIAL",
			iakCertNotBefore:        time.Now().Add(-1 * time.Hour),
			iakCertNotAfter:         time.Now().AddDate(0, 0, 10),
			iDevIDCertAsymAlgo:      eccP384Algo,
			iDevIDCertSubjectSerial: "SERIAL",
			iDevIDCertNotBefore:     time.Now().Add(-1 * time.Hour),
			iDevIDCertNotAfter:      time.Now().AddDate(0, 0, 10),
		},
		{
			desc:                    "Failure: unsupported ED25519 algo for IDevID",
			wantError:               true,
			cardID:                  cardID,
			iakCertAsymAlgo:         eccP384Algo,
			iakCertSubjectSerial:    "SERIAL",
			iakCertNotBefore:        time.Now().Add(-1 * time.Hour),
			iakCertNotAfter:         time.Now().AddDate(0, 0, 10),
			iDevIDCertAsymAlgo:      ed25519Algo,
			iDevIDCertSubjectSerial: "SERIAL",
			iDevIDCertNotBefore:     time.Now().Add(-1 * time.Hour),
			iDevIDCertNotAfter:      time.Now().AddDate(0, 0, 10),
		},
		{
			desc:                    "Failure: RSA key length lower than 2048 for IAK",
			wantError:               true,
			cardID:                  cardID,
			iakCertAsymAlgo:         rsa1024Algo,
			iakCertSubjectSerial:    "SERIAL",
			iakCertNotBefore:        time.Now().Add(-1 * time.Hour),
			iakCertNotAfter:         time.Now().AddDate(0, 0, 10),
			iDevIDCertAsymAlgo:      eccP384Algo,
			iDevIDCertSubjectSerial: "SERIAL",
			iDevIDCertNotBefore:     time.Now().Add(-1 * time.Hour),
			iDevIDCertNotAfter:      time.Now().AddDate(1, 0, 0),
		},
		{
			desc:                    "Failure: RSA key length lower than 2048 for IDevID",
			wantError:               true,
			cardID:                  cardID,
			iakCertAsymAlgo:         eccP384Algo,
			iakCertSubjectSerial:    "SERIAL",
			iakCertNotBefore:        time.Now().Add(-1 * time.Hour),
			iakCertNotAfter:         time.Now().AddDate(0, 0, 10),
			iDevIDCertAsymAlgo:      rsa1024Algo,
			iDevIDCertSubjectSerial: "SERIAL",
			iDevIDCertNotBefore:     time.Now().Add(-1 * time.Hour),
			iDevIDCertNotAfter:      time.Now().AddDate(1, 0, 0),
		},
		{
			desc:                    "Failure: ECC key length lower than 256 for IAK",
			wantError:               true,
			cardID:                  cardID,
			iakCertAsymAlgo:         eccP224Algo,
			iakCertSubjectSerial:    "SERIAL",
			iakCertNotBefore:        time.Now().Add(-1 * time.Hour),
			iakCertNotAfter:         time.Now().AddDate(0, 0, 10),
			iDevIDCertAsymAlgo:      eccP384Algo,
			iDevIDCertSubjectSerial: "SERIAL",
			iDevIDCertNotBefore:     time.Now().Add(-1 * time.Hour),
			iDevIDCertNotAfter:      time.Now().AddDate(1, 0, 0),
		},
		{
			desc:                    "Failure: ECC key length lower than 256 for IDevID",
			wantError:               true,
			cardID:                  cardID,
			iakCertAsymAlgo:         eccP384Algo,
			iakCertSubjectSerial:    "SERIAL",
			iakCertNotBefore:        time.Now().Add(-1 * time.Hour),
			iakCertNotAfter:         time.Now().AddDate(0, 0, 10),
			iDevIDCertAsymAlgo:      eccP224Algo,
			iDevIDCertSubjectSerial: "SERIAL",
			iDevIDCertNotBefore:     time.Now().Add(-1 * time.Hour),
			iDevIDCertNotAfter:      time.Now().AddDate(1, 0, 0),
		},
		{
			desc:                    "Failure: malformed PEM IAK cert",
			wantError:               true,
			cardID:                  cardID,
			iakCertAsymAlgo:         eccP384Algo,
			iakCertSubjectSerial:    "SERIAL",
			iakCertNotBefore:        time.Now().Add(-1 * time.Hour),
			iakCertNotAfter:         time.Now().AddDate(0, 0, 10),
			iDevIDCertAsymAlgo:      eccP384Algo,
			iDevIDCertSubjectSerial: "SERIAL",
			iDevIDCertNotBefore:     time.Now().Add(-1 * time.Hour),
			iDevIDCertNotAfter:      time.Now().AddDate(1, 0, 0),
			customIakCertPem:        "BAD HEADER\nsome payload\nBAD FOOTER\n",
		},
		{
			desc:                    "Failure: malformed PEM IDevID cert",
			wantError:               true,
			cardID:                  cardID,
			iakCertAsymAlgo:         eccP384Algo,
			iakCertSubjectSerial:    "SERIAL",
			iakCertNotBefore:        time.Now().Add(-1 * time.Hour),
			iakCertNotAfter:         time.Now().AddDate(0, 0, 10),
			iDevIDCertAsymAlgo:      eccP384Algo,
			iDevIDCertSubjectSerial: "SERIAL",
			iDevIDCertNotBefore:     time.Now().Add(-1 * time.Hour),
			iDevIDCertNotAfter:      time.Now().AddDate(1, 0, 0),
			customIDevIDCertPem:     "BAD HEADER\nsome payload\nBAD FOOTER\n",
		},
		{
			desc:                    "Failure: IAK cert is expired",
			wantError:               true,
			cardID:                  cardID,
			iakCertAsymAlgo:         eccP384Algo,
			iakCertSubjectSerial:    "SERIAL",
			iakCertNotBefore:        time.Now().AddDate(0, 0, -20),
			iakCertNotAfter:         time.Now().AddDate(0, 0, -10),
			iDevIDCertAsymAlgo:      eccP384Algo,
			iDevIDCertSubjectSerial: "SERIAL",
			iDevIDCertNotBefore:     time.Now().Add(-1 * time.Hour),
			iDevIDCertNotAfter:      time.Now().AddDate(1, 0, 0),
		},
		{
			desc:                    "Failure: IDevID cert is expired",
			wantError:               true,
			cardID:                  cardID,
			iakCertAsymAlgo:         eccP384Algo,
			iakCertSubjectSerial:    "SERIAL",
			iakCertNotBefore:        time.Now().Add(-1 * time.Hour),
			iakCertNotAfter:         time.Now().AddDate(1, 0, 0),
			iDevIDCertAsymAlgo:      eccP384Algo,
			iDevIDCertSubjectSerial: "SERIAL",
			iDevIDCertNotBefore:     time.Now().AddDate(-2, 0, 0),
			iDevIDCertNotAfter:      time.Now().AddDate(-1, 0, 0),
		},
		{
			desc:                    "Failure: cannot validate IAK cert signature",
			wantError:               true,
			cardID:                  cardID,
			iakCertAsymAlgo:         rsa4096Algo,
			iakCertSubjectSerial:    "SERIAL",
			iakCertNotBefore:        time.Now().Add(-1 * time.Hour),
			iakCertNotAfter:         time.Now().AddDate(0, 0, 10),
			iDevIDCertAsymAlgo:      eccP384Algo,
			iDevIDCertSubjectSerial: "SERIAL",
			iDevIDCertNotBefore:     time.Now().Add(-1 * time.Hour),
			iDevIDCertNotAfter:      time.Now().AddDate(1, 0, 0),
			customIakCaRootPem:      unknownCaCert.certPem,
		},
		{
			desc:                    "Failure: cannot validate IDevID cert signature",
			wantError:               true,
			cardID:                  cardID,
			iakCertAsymAlgo:         rsa4096Algo,
			iakCertSubjectSerial:    "SERIAL",
			iakCertNotBefore:        time.Now().Add(-1 * time.Hour),
			iakCertNotAfter:         time.Now().AddDate(0, 0, 10),
			iDevIDCertAsymAlgo:      eccP384Algo,
			iDevIDCertSubjectSerial: "SERIAL",
			iDevIDCertNotBefore:     time.Now().Add(-1 * time.Hour),
			iDevIDCertNotAfter:      time.Now().AddDate(1, 0, 0),
			customIDevIDCaRootPem:   unknownCaCert.certPem,
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			verifier := &tpmCertVerifierSansSN{}
			ctx := context.Background()

			if test.nilReq {
				gotResp, gotErr := verifier.VerifyIakAndIDevIDCerts(ctx, nil)
				if gotErr == nil {
					t.Fatalf("Expected error for nil req, got response: %+v", gotResp)
				}
				return
			}

			genIakCaCert := generateCaCert(t)
			genIakCert := generateSignedCert(t, &certCreationParams{
				asymAlgo:          test.iakCertAsymAlgo,
				certSubjectSerial: test.iakCertSubjectSerial,
				signingCert:       genIakCaCert.certX509,
				signingPrivKey:    genIakCaCert.privKey,
				notBefore:         test.iakCertNotBefore,
				notAfter:          test.iakCertNotAfter,
			})

			wantIakPubPem := genIakCert.pubKeyPem
			iakCertPemReq := genIakCert.certPem
			if test.customIakCertPem != "" {
				iakCertPemReq = test.customIakCertPem
			}
			iakCaCertPemReq := genIakCaCert.certPem
			if test.customIakCaRootPem != "" {
				iakCaCertPemReq = test.customIakCaRootPem
			}

			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM([]byte(iakCaCertPemReq)) {
				t.Fatalf("Test setup failed! Unable to append IAK CA cert to pool: %s", iakCaCertPemReq)
			}

			wantIDevIDPubPem := ""
			iDevIDCertPemReq := ""
			if !test.noIDevID {
				genIDevIDCaCert := generateCaCert(t)
				genIDevIDCert := generateSignedCert(t, &certCreationParams{
					asymAlgo:          test.iDevIDCertAsymAlgo,
					certSubjectSerial: test.iDevIDCertSubjectSerial,
					signingCert:       genIDevIDCaCert.certX509,
					signingPrivKey:    genIDevIDCaCert.privKey,
					notBefore:         test.iDevIDCertNotBefore,
					notAfter:          test.iDevIDCertNotAfter,
				})

				wantIDevIDPubPem = genIDevIDCert.pubKeyPem
				iDevIDCertPemReq = genIDevIDCert.certPem
				if test.customIDevIDCertPem != "" {
					iDevIDCertPemReq = test.customIDevIDCertPem
				}
				iDevIDCaCertPemReq := genIDevIDCaCert.certPem
				if test.customIDevIDCaRootPem != "" {
					iDevIDCaCertPemReq = test.customIDevIDCaRootPem
				}
				if !roots.AppendCertsFromPEM([]byte(iDevIDCaCertPemReq)) {
					t.Fatalf("Test setup failed! Unable to append IDevID CA cert to pool: %s", iDevIDCaCertPemReq)
				}
			}

			req := &biz.VerifyIakAndIDevIDCertsReq{
				ControlCardID:        test.cardID,
				IakCertPem:           iakCertPemReq,
				IDevIDCertPem:        iDevIDCertPemReq,
				CertVerificationOpts: x509.VerifyOptions{Roots: roots},
			}

			gotResp, gotErr := verifier.VerifyIakAndIDevIDCerts(ctx, req)
			if test.wantError {
				if gotErr == nil {
					t.Fatalf("Expected error response, but got response: %+v", gotResp)
				}
			} else {
				if gotErr != nil {
					t.Fatalf("Expected successful response, but got error: %v", gotErr)
				}
				if diff := cmp.Diff(gotResp.IakPubPem, wantIakPubPem); diff != "" {
					t.Errorf("IAK pub PEM mismatch: diff = %v", diff)
				}
				if diff := cmp.Diff(gotResp.IDevIDPubPem, wantIDevIDPubPem); diff != "" {
					t.Errorf("IDevID pub PEM mismatch: diff = %v", diff)
				}
			}
		})
	}
}

func TestVerifyTpmCertSansSN(t *testing.T) {
	unknownCaCert := generateCaCert(t)

	cardID := &cpb.ControlCardVendorId{
		ControlCardRole:     cpb.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE,
		ControlCardSerial:   "SOME-CARD-SERIAL",
		ChassisSerialNumber: "SOME-CHASSIS-SERIAL",
	}

	tests := []struct {
		desc               string
		wantError          bool
		certAsymAlgo       asymAlgo
		certSubjectSerial  string
		certNotBefore      time.Time
		certNotAfter       time.Time
		useIntermediateCA  bool
		includeRootInChain bool
		customCertPem      string
		customCaRootPem    string
		nilReq             bool
	}{
		{
			desc:              "Success: Mismatched serial number",
			wantError:         false,
			certAsymAlgo:      rsa4096Algo,
			certSubjectSerial: "TOTALLY-DIFFERENT-SERIAL",
			certNotBefore:     time.Now().Add(-1 * time.Hour),
			certNotAfter:      time.Now().AddDate(0, 0, 10),
		},
		{
			desc:              "Success: RSA 2048 cert",
			wantError:         false,
			certAsymAlgo:      rsa2048Algo,
			certSubjectSerial: "SERIAL-1",
			certNotBefore:     time.Now().Add(-1 * time.Hour),
			certNotAfter:      time.Now().AddDate(0, 1, 0),
		},
		{
			desc:              "Success: ECC P256 cert",
			wantError:         false,
			certAsymAlgo:      eccP256Algo,
			certSubjectSerial: "",
			certNotBefore:     time.Now().Add(-1 * time.Hour),
			certNotAfter:      time.Now().AddDate(1, 0, 0),
		},
		{
			desc:              "Success: ECC P384 cert with intermediate CA",
			wantError:         false,
			certAsymAlgo:      eccP384Algo,
			certSubjectSerial: "SOME-SERIAL",
			certNotBefore:     time.Now().Add(-1 * time.Hour),
			certNotAfter:      time.Now().AddDate(1, 0, 0),
			useIntermediateCA: true,
		},
		{
			desc:               "Success: ECC P384 cert with intermediate and root CA in chain",
			wantError:          false,
			certAsymAlgo:       eccP384Algo,
			certSubjectSerial:  "SOME-SERIAL",
			certNotBefore:      time.Now().Add(-1 * time.Hour),
			certNotAfter:       time.Now().AddDate(1, 0, 0),
			useIntermediateCA:  true,
			includeRootInChain: true,
		},
		{
			desc:      "Failure: Nil request",
			wantError: true,
			nilReq:    true,
		},
		{
			desc:              "Failure: unsupported ED25519 algo",
			wantError:         true,
			certAsymAlgo:      ed25519Algo,
			certSubjectSerial: "SERIAL",
			certNotBefore:     time.Now().Add(-1 * time.Hour),
			certNotAfter:      time.Now().AddDate(0, 0, 10),
		},
		{
			desc:              "Failure: RSA key length lower than 2048",
			wantError:         true,
			certAsymAlgo:      rsa1024Algo,
			certSubjectSerial: "SERIAL",
			certNotBefore:     time.Now().Add(-1 * time.Hour),
			certNotAfter:      time.Now().AddDate(0, 0, 10),
		},
		{
			desc:              "Failure: ECC key length lower than 256",
			wantError:         true,
			certAsymAlgo:      eccP224Algo,
			certSubjectSerial: "SERIAL",
			certNotBefore:     time.Now().Add(-1 * time.Hour),
			certNotAfter:      time.Now().AddDate(0, 0, 10),
		},
		{
			desc:              "Failure: malformed PEM cert",
			wantError:         true,
			certAsymAlgo:      eccP384Algo,
			certSubjectSerial: "SERIAL",
			certNotBefore:     time.Now().Add(-1 * time.Hour),
			certNotAfter:      time.Now().AddDate(0, 0, 10),
			customCertPem:     "BAD HEADER\nsome payload\nBAD FOOTER\n",
		},
		{
			desc:              "Failure: cert is expired",
			wantError:         true,
			certAsymAlgo:      eccP384Algo,
			certSubjectSerial: "SERIAL",
			certNotBefore:     time.Now().AddDate(0, 0, -20),
			certNotAfter:      time.Now().AddDate(0, 0, -10),
		},
		{
			desc:            "Failure: cannot validate cert signature",
			wantError:       true,
			certAsymAlgo:    rsa4096Algo,
			certNotBefore:   time.Now().Add(-1 * time.Hour),
			certNotAfter:    time.Now().AddDate(0, 0, 10),
			customCaRootPem: unknownCaCert.certPem,
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			verifier := &tpmCertVerifierSansSN{}
			ctx := context.Background()

			if test.nilReq {
				gotResp, gotErr := verifier.VerifyTpmCert(ctx, nil)
				if gotErr == nil {
					t.Fatalf("Expected error for nil req, got response: %+v", gotResp)
				}
				return
			}

			genCaCert := generateCaCert(t)
			var genTpmCert *signedTpmCert
			var certPemReq string

			if test.useIntermediateCA {
				interCa := generateInterCaCert(t, genCaCert.certX509, genCaCert.privKey)
				genTpmCert = generateSignedCert(t, &certCreationParams{
					asymAlgo:          test.certAsymAlgo,
					certSubjectSerial: test.certSubjectSerial,
					signingCert:       interCa.certX509,
					signingPrivKey:    interCa.privKey,
					notBefore:         test.certNotBefore,
					notAfter:          test.certNotAfter,
				})
				certPemReq = genTpmCert.certPem + interCa.certPem
			} else {
				genTpmCert = generateSignedCert(t, &certCreationParams{
					asymAlgo:          test.certAsymAlgo,
					certSubjectSerial: test.certSubjectSerial,
					signingCert:       genCaCert.certX509,
					signingPrivKey:    genCaCert.privKey,
					notBefore:         test.certNotBefore,
					notAfter:          test.certNotAfter,
				})
				certPemReq = genTpmCert.certPem
			}

			if test.includeRootInChain {
				certPemReq += genCaCert.certPem
			}

			wantCertPubPem := genTpmCert.pubKeyPem
			if test.customCertPem != "" {
				certPemReq = test.customCertPem
			}

			roots := x509.NewCertPool()
			caCertPemReq := genCaCert.certPem
			if test.customCaRootPem != "" {
				caCertPemReq = test.customCaRootPem
			}
			if !roots.AppendCertsFromPEM([]byte(caCertPemReq)) {
				t.Fatalf("Test setup failed! Unable to append CA cert to pool: %s", caCertPemReq)
			}

			req := &biz.VerifyTpmCertReq{
				ControlCardID:        cardID,
				CertPem:              certPemReq,
				CertVerificationOpts: x509.VerifyOptions{Roots: roots},
			}

			gotResp, gotErr := verifier.VerifyTpmCert(ctx, req)
			if test.wantError {
				if gotErr == nil {
					t.Fatalf("Expected error response, but got response: %+v", gotResp)
				}
			} else {
				if gotErr != nil {
					t.Fatalf("Expected successful response, but got error: %v", gotErr)
				}
				if diff := cmp.Diff(gotResp.PubPem, wantCertPubPem); diff != "" {
					t.Errorf("Cert pub PEM mismatch: diff = %v", diff)
				}
			}
		})
	}
}
