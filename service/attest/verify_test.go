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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	apb "github.com/openconfig/attestz/proto/tpm_attestz"
)

type testCertChain struct {
	rootCert      *x509.Certificate
	interCert     *x509.Certificate
	interKey      *rsa.PrivateKey
	oiakCert      *x509.Certificate
	oiakKey       *rsa.PrivateKey
	oiakPEM       string
	rootPool      *x509.CertPool
	interPool     *x509.CertPool
	untrustedPool *x509.CertPool
}

func generateTestCertChain(t *testing.T) *testCertChain {
	t.Helper()

	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate root RSA key: %v", err)
	}

	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Root CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("failed to create root cert: %v", err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("failed to parse root cert: %v", err)
	}

	interKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate intermediate RSA key: %v", err)
	}

	interTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "Test Intermediate CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	interDER, err := x509.CreateCertificate(rand.Reader, interTemplate, rootCert, &interKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("failed to create intermediate cert: %v", err)
	}
	interCert, err := x509.ParseCertificate(interDER)
	if err != nil {
		t.Fatalf("failed to parse intermediate cert: %v", err)
	}

	oiakKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate OIAK RSA key: %v", err)
	}

	oiakTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			CommonName: "Test OIAK",
		},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	oiakDER, err := x509.CreateCertificate(rand.Reader, oiakTemplate, interCert, &oiakKey.PublicKey, interKey)
	if err != nil {
		t.Fatalf("failed to create OIAK cert: %v", err)
	}
	oiakCert, err := x509.ParseCertificate(oiakDER)
	if err != nil {
		t.Fatalf("failed to parse OIAK cert: %v", err)
	}

	oiakPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: oiakDER})

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	interPool := x509.NewCertPool()
	interPool.AddCert(interCert)

	untrustedPool := x509.NewCertPool()

	return &testCertChain{
		rootCert:      rootCert,
		interCert:     interCert,
		interKey:      interKey,
		oiakCert:      oiakCert,
		oiakKey:       oiakKey,
		oiakPEM:       string(oiakPEM),
		rootPool:      rootPool,
		interPool:     interPool,
		untrustedPool: untrustedPool,
	}
}

func createAttestResponse(oiakPEM string, quoted, sig []byte, pcrValues map[int32][]byte) *apb.AttestResponse {
	return &apb.AttestResponse{
		AttestationCert: &apb.AttestResponse_AttestationCert{
			Value: &apb.AttestResponse_AttestationCert_OiakCert{
				OiakCert: oiakPEM,
			},
		},
		Quoted:         quoted,
		QuoteSignature: sig,
		PcrValues:      pcrValues,
	}
}

func createValidQuote(t *testing.T, requestedIndices []int, pcrValues map[int32][]byte, nonce []byte, key *rsa.PrivateKey) ([]byte, []byte) {
	t.Helper()

	var sortedIndices []int
	sortedIndices = append(sortedIndices, requestedIndices...)
	sort.Ints(sortedIndices)

	pcrBitmask := make([]byte, 3)
	for _, idx := range sortedIndices {
		if idx >= 0 && idx <= 23 {
			pcrBitmask[idx/8] |= (1 << (idx % 8))
		}
	}

	expectedPcrSelect := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      tpm2.TPMAlgSHA256,
				PCRSelect: pcrBitmask,
			},
		},
	}

	var pcrConcat []byte
	for _, idx := range sortedIndices {
		val, ok := pcrValues[int32(idx)]
		if !ok {
			t.Fatalf("missing PCR index %d in pcrValues", idx)
		}
		pcrConcat = append(pcrConcat, val...)
	}
	reportedDigest := sha256.Sum256(pcrConcat)

	attest := tpm2.TPMSAttest{
		Magic:     tpm2.TPMGeneratedValue,
		Type:      tpm2.TPMSTAttestQuote,
		ExtraData: tpm2.TPM2BData{Buffer: nonce},
		Attested: tpm2.NewTPMUAttest(tpm2.TPMSTAttestQuote, &tpm2.TPMSQuoteInfo{
			PCRSelect: expectedPcrSelect,
			PCRDigest: tpm2.TPM2BDigest{Buffer: reportedDigest[:]},
		}),
	}

	quoted := tpm2.Marshal(attest)
	hash := sha256.Sum256(quoted)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatalf("failed to sign quote: %v", err)
	}

	return quoted, sig
}

func TestVerifyRemoteAttestationSuccess(t *testing.T) {
	chain := generateTestCertChain(t)

	requestedIndices := []int{0, 4, 7}
	pcrValues := map[int32][]byte{
		0: bytesRepeat(0x01, 32),
		4: bytesRepeat(0x02, 32),
		7: bytesRepeat(0x03, 32),
	}
	expectedPCRs := map[int][]byte{
		0: bytesRepeat(0x01, 32),
		4: bytesRepeat(0x02, 32),
		7: bytesRepeat(0x03, 32),
	}
	expectedNonce := []byte("test-random-nonce-12345678901234")

	quoted, sig := createValidQuote(t, requestedIndices, pcrValues, expectedNonce, chain.oiakKey)

	resp := createAttestResponse(chain.oiakPEM, quoted, sig, pcrValues)

	if err := VerifyRemoteAttestation(resp, expectedPCRs, requestedIndices, expectedNonce, chain.rootPool, chain.interPool); err != nil {
		t.Fatalf("VerifyRemoteAttestation() failed unexpectedly: %v", err)
	}
}

func TestVerifyRemoteAttestationCertificateErrors(t *testing.T) {
	chain := generateTestCertChain(t)
	requestedIndices := []int{0}
	pcrValues := map[int32][]byte{0: bytesRepeat(0xAA, 32)}
	expectedPCRs := map[int][]byte{0: bytesRepeat(0xAA, 32)}
	nonce := []byte("test-nonce")
	quoted, sig := createValidQuote(t, requestedIndices, pcrValues, nonce, chain.oiakKey)

	t.Run("InvalidPEM", func(t *testing.T) {
		resp := createAttestResponse("not-a-valid-pem", quoted, sig, pcrValues)
		err := VerifyRemoteAttestation(resp, expectedPCRs, requestedIndices, nonce, chain.rootPool, chain.interPool)
		if err == nil || !strings.Contains(err.Error(), "failed to decode OIAK PEM block") {
			t.Errorf("expected error 'failed to decode OIAK PEM block', got: %v", err)
		}
	})

	t.Run("InvalidCertBytes", func(t *testing.T) {
		corruptedPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("corrupted certificate bytes")})
		resp := createAttestResponse(string(corruptedPEM), quoted, sig, pcrValues)
		err := VerifyRemoteAttestation(resp, expectedPCRs, requestedIndices, nonce, chain.rootPool, chain.interPool)
		if err == nil || !strings.Contains(err.Error(), "failed to parse OIAK certificate") {
			t.Errorf("expected error 'failed to parse OIAK certificate', got: %v", err)
		}
	})

	t.Run("UntrustedChain", func(t *testing.T) {
		resp := createAttestResponse(chain.oiakPEM, quoted, sig, pcrValues)
		err := VerifyRemoteAttestation(resp, expectedPCRs, requestedIndices, nonce, chain.untrustedPool, chain.interPool)
		if err == nil || !strings.Contains(err.Error(), "certificate chain of trust validation failed") {
			t.Errorf("expected error 'certificate chain of trust validation failed', got: %v", err)
		}
	})

	t.Run("NonRSAPublicKey", func(t *testing.T) {
		ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate ecdsa key: %v", err)
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(99),
			Subject:      pkix.Name{CommonName: "ECDSA Cert"},
			NotBefore:    time.Now().Add(-1 * time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}
		ecdsaDER, err := x509.CreateCertificate(rand.Reader, template, chain.interCert, &ecdsaKey.PublicKey, chain.interKey)
		if err != nil {
			t.Fatalf("failed to create ecdsa cert: %v", err)
		}
		ecdsaPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ecdsaDER})

		resp := createAttestResponse(string(ecdsaPEM), quoted, sig, pcrValues)
		err = VerifyRemoteAttestation(resp, expectedPCRs, requestedIndices, nonce, chain.rootPool, chain.interPool)
		if err == nil || !strings.Contains(err.Error(), "OIAK certificate does not contain an RSA public key") {
			t.Errorf("expected error 'OIAK certificate does not contain an RSA public key', got: %v", err)
		}
	})
}

func TestVerifyRemoteAttestationSignatureError(t *testing.T) {
	chain := generateTestCertChain(t)
	requestedIndices := []int{0}
	pcrValues := map[int32][]byte{0: bytesRepeat(0xAA, 32)}
	expectedPCRs := map[int][]byte{0: bytesRepeat(0xAA, 32)}
	nonce := []byte("test-nonce")
	quoted, sig := createValidQuote(t, requestedIndices, pcrValues, nonce, chain.oiakKey)

	// Tamper with the signature.
	corruptedSig := make([]byte, len(sig))
	copy(corruptedSig, sig)
	corruptedSig[0] ^= 0xFF

	resp := createAttestResponse(chain.oiakPEM, quoted, corruptedSig, pcrValues)

	err := VerifyRemoteAttestation(resp, expectedPCRs, requestedIndices, nonce, chain.rootPool, chain.interPool)
	if err == nil || !strings.Contains(err.Error(), "quote signature verification failed") {
		t.Errorf("expected error 'quote signature verification failed', got: %v", err)
	}
}

func TestVerifyRemoteAttestationQuoteErrors(t *testing.T) {
	chain := generateTestCertChain(t)
	requestedIndices := []int{0, 4}
	pcrValues := map[int32][]byte{
		0: bytesRepeat(0x11, 32),
		4: bytesRepeat(0x22, 32),
	}
	expectedPCRs := map[int][]byte{
		0: bytesRepeat(0x11, 32),
		4: bytesRepeat(0x22, 32),
	}
	nonce := []byte("test-nonce-12345")

	t.Run("BadAttestationBytes", func(t *testing.T) {
		corruptedQuoted := []byte("not-a-tpms-attest-structure")
		hash := sha256.Sum256(corruptedQuoted)
		sig, _ := rsa.SignPKCS1v15(rand.Reader, chain.oiakKey, crypto.SHA256, hash[:])

		resp := createAttestResponse(chain.oiakPEM, corruptedQuoted, sig, pcrValues)
		err := VerifyRemoteAttestation(resp, expectedPCRs, requestedIndices, nonce, chain.rootPool, chain.interPool)
		if err == nil || !strings.Contains(err.Error(), "bad Quote attestation") {
			t.Errorf("expected error 'bad Quote attestation', got: %v", err)
		}
	})

	t.Run("WrongMagicValue", func(t *testing.T) {
		attest := tpm2.TPMSAttest{
			Magic:     0x12345678, // Wrong magic
			Type:      tpm2.TPMSTAttestQuote,
			ExtraData: tpm2.TPM2BData{Buffer: nonce},
			Attested: tpm2.NewTPMUAttest(tpm2.TPMSTAttestQuote, &tpm2.TPMSQuoteInfo{
				PCRSelect: tpm2.TPMLPCRSelection{
					PCRSelections: []tpm2.TPMSPCRSelection{{Hash: tpm2.TPMAlgSHA256, PCRSelect: []byte{0x11, 0x00, 0x00}}},
				},
				PCRDigest: tpm2.TPM2BDigest{Buffer: bytesRepeat(0x00, 32)},
			}),
		}
		quoted := tpm2.Marshal(attest)
		hash := sha256.Sum256(quoted)
		sig, _ := rsa.SignPKCS1v15(rand.Reader, chain.oiakKey, crypto.SHA256, hash[:])

		resp := createAttestResponse(chain.oiakPEM, quoted, sig, pcrValues)
		err := VerifyRemoteAttestation(resp, expectedPCRs, requestedIndices, nonce, chain.rootPool, chain.interPool)
		if err == nil || !strings.Contains(err.Error(), "wrong magic value") {
			t.Errorf("expected error 'wrong magic value', got: %v", err)
		}
	})

	t.Run("WrongQuoteAttestationType", func(t *testing.T) {
		attest := tpm2.TPMSAttest{
			Magic:     tpm2.TPMGeneratedValue,
			Type:      tpm2.TPMSTAttestCertify, // Wrong type
			ExtraData: tpm2.TPM2BData{Buffer: nonce},
			Attested:  tpm2.NewTPMUAttest(tpm2.TPMSTAttestCertify, &tpm2.TPMSCertifyInfo{}),
		}
		quoted := tpm2.Marshal(attest)
		hash := sha256.Sum256(quoted)
		sig, _ := rsa.SignPKCS1v15(rand.Reader, chain.oiakKey, crypto.SHA256, hash[:])

		resp := createAttestResponse(chain.oiakPEM, quoted, sig, pcrValues)
		err := VerifyRemoteAttestation(resp, expectedPCRs, requestedIndices, nonce, chain.rootPool, chain.interPool)
		if err == nil || !strings.Contains(err.Error(), "wrong Quote attestation type") {
			t.Errorf("expected error 'wrong Quote attestation type', got: %v", err)
		}
	})

	t.Run("NonceMismatch", func(t *testing.T) {
		wrongNonce := []byte("different-nonce-12345")
		quoted, sig := createValidQuote(t, requestedIndices, pcrValues, wrongNonce, chain.oiakKey)

		resp := createAttestResponse(chain.oiakPEM, quoted, sig, pcrValues)
		err := VerifyRemoteAttestation(resp, expectedPCRs, requestedIndices, nonce, chain.rootPool, chain.interPool)
		if err == nil || !strings.Contains(err.Error(), "wrong nonce") {
			t.Errorf("expected error 'wrong nonce', got: %v", err)
		}
	})

	t.Run("PCRSelectionMismatch", func(t *testing.T) {
		// Quote contains PCR selection for indices {0} instead of {0, 4}.
		quoted, sig := createValidQuote(t, []int{0}, pcrValues, nonce, chain.oiakKey)

		resp := createAttestResponse(chain.oiakPEM, quoted, sig, pcrValues)
		err := VerifyRemoteAttestation(resp, expectedPCRs, requestedIndices, nonce, chain.rootPool, chain.interPool)
		if err == nil || !strings.Contains(err.Error(), "PCR selection strictly mismatched against requested quote indices") {
			t.Errorf("expected error 'PCR selection strictly mismatched against requested quote indices', got: %v", err)
		}
	})
}

func TestVerifyRemoteAttestationPCRValuesErrors(t *testing.T) {
	chain := generateTestCertChain(t)
	requestedIndices := []int{0, 4}
	pcrValues := map[int32][]byte{
		0: bytesRepeat(0x11, 32),
		4: bytesRepeat(0x22, 32),
	}
	expectedPCRs := map[int][]byte{
		0: bytesRepeat(0x11, 32),
		4: bytesRepeat(0x22, 32),
	}
	nonce := []byte("test-nonce-12345")
	quoted, sig := createValidQuote(t, requestedIndices, pcrValues, nonce, chain.oiakKey)

	t.Run("MissingRequestedPCR", func(t *testing.T) {
		incompletePCRValues := map[int32][]byte{
			0: bytesRepeat(0x11, 32),
		}
		resp := createAttestResponse(chain.oiakPEM, quoted, sig, incompletePCRValues)
		err := VerifyRemoteAttestation(resp, expectedPCRs, requestedIndices, nonce, chain.rootPool, chain.interPool)
		if err == nil || !strings.Contains(err.Error(), "device failed to map standard requested PCR index 4") {
			t.Errorf("expected error 'device failed to map standard requested PCR index 4', got: %v", err)
		}
	})

	t.Run("PCRCompositeDigestMismatch", func(t *testing.T) {
		tamperedPCRValues := map[int32][]byte{
			0: bytesRepeat(0x11, 32),
			4: bytesRepeat(0x99, 32), // tampered value
		}
		resp := createAttestResponse(chain.oiakPEM, quoted, sig, tamperedPCRValues)
		err := VerifyRemoteAttestation(resp, expectedPCRs, requestedIndices, nonce, chain.rootPool, chain.interPool)
		if err == nil || !strings.Contains(err.Error(), "integrity violation: raw PCR values provided do not logically yield the quote's PCR digest") {
			t.Errorf("expected error 'integrity violation: raw PCR values provided do not logically yield the quote's PCR digest', got: %v", err)
		}
	})

	t.Run("MissingExpectedPCRPolicy", func(t *testing.T) {
		expPCRs := map[int][]byte{
			0: bytesRepeat(0x11, 32),
			4: bytesRepeat(0x22, 32),
			8: bytesRepeat(0x33, 32), // PCR 8 not in resp.PcrValues
		}
		resp := createAttestResponse(chain.oiakPEM, quoted, sig, pcrValues)
		err := VerifyRemoteAttestation(resp, expPCRs, requestedIndices, nonce, chain.rootPool, chain.interPool)
		if err == nil || !strings.Contains(err.Error(), "policy failure: expected PCR 8 was totally absent from payload") {
			t.Errorf("expected error 'policy failure: expected PCR 8 was totally absent from payload', got: %v", err)
		}
	})

	t.Run("ExpectedPCRValueMismatchPolicy", func(t *testing.T) {
		expPCRs := map[int][]byte{
			0: bytesRepeat(0xFF, 32), // mismatch against reported 0x11
			4: bytesRepeat(0x22, 32),
		}
		resp := createAttestResponse(chain.oiakPEM, quoted, sig, pcrValues)
		err := VerifyRemoteAttestation(resp, expPCRs, requestedIndices, nonce, chain.rootPool, chain.interPool)
		if err == nil || !strings.Contains(err.Error(), "policy failure: PCR 0 expected") {
			t.Errorf("expected error 'policy failure: PCR 0 expected ...', got: %v", err)
		}
	})
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
