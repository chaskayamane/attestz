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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	cpb "github.com/openconfig/attestz/proto/common_definitions"
)

func TestCreateAttestRequest(t *testing.T) {
	// Unspecified hash algorithm should default to SHA384.
	reqDefault, err := createAttestRequest(cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_UNSPECIFIED)
	if err != nil {
		t.Fatalf("createAttestRequest(UNSPECIFIED) failed: %v", err)
	}
	if reqDefault.GetHashAlgo() != cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA384 {
		t.Errorf("default HashAlgo = %v, want %v", reqDefault.GetHashAlgo(), cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA384)
	}

	// Explicit SHA256.
	req256, err := createAttestRequest(cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA256)
	if err != nil {
		t.Fatalf("createAttestRequest(SHA256) failed: %v", err)
	}
	if req256.GetHashAlgo() != cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA256 {
		t.Errorf("HashAlgo = %v, want %v", req256.GetHashAlgo(), cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA256)
	}

	// Explicit SHA384.
	req384, err := createAttestRequest(cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA384)
	if err != nil {
		t.Fatalf("createAttestRequest(SHA384) failed: %v", err)
	}
	if req384.GetHashAlgo() != cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA384 {
		t.Errorf("HashAlgo = %v, want %v", req384.GetHashAlgo(), cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA384)
	}

	// Verify ControlCardSelection role is ACTIVE.
	role := req384.GetControlCardSelection().GetRole()
	if role != cpb.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE {
		t.Errorf("ControlCardSelection role = %v, want %v", role, cpb.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE)
	}

	// Verify Nonce is 32 bytes.
	if len(req384.GetNonce()) != 32 {
		t.Errorf("Nonce length = %d, want 32", len(req384.GetNonce()))
	}

	// Verify PcrIndices default to [0, 4, 7].
	wantPcr := []int32{0, 4, 7}
	if diff := cmp.Diff(wantPcr, req384.GetPcrIndices()); diff != "" {
		t.Errorf("PcrIndices mismatch (-want +got):\n%s", diff)
	}

	// Verify Nonce is random by checking that successive calls produce different nonces.
	reqAnother, err := createAttestRequest(cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA384)
	if err != nil {
		t.Fatalf("second createAttestRequest() failed: %v", err)
	}
	if bytes.Equal(req384.GetNonce(), reqAnother.GetNonce()) {
		t.Errorf("Nonces are identical across calls: %x", req384.GetNonce())
	}
}

func TestParseHashAlgo(t *testing.T) {
	tests := []struct {
		input   string
		want    cpb.Tpm20HashAlgo
		wantErr bool
	}{
		{input: "SHA256", want: cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA256},
		{input: "sha256", want: cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA256},
		{input: "TPM_2_0_HASH_ALGO_SHA256", want: cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA256},
		{input: "SHA384", want: cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA384},
		{input: "sha384", want: cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA384},
		{input: "TPM_2_0_HASH_ALGO_SHA384", want: cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA384},
		{input: "  sha384  ", want: cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA384},
		{input: "SHA512", wantErr: true},
		{input: "invalid", wantErr: true},
		{input: "", wantErr: true},
	}
	for _, tc := range tests {
		got, err := parseHashAlgo(tc.input)
		if (err != nil) != tc.wantErr {
			t.Errorf("parseHashAlgo(%q) error = %v, wantErr %v", tc.input, err, tc.wantErr)
		}
		if !tc.wantErr && got != tc.want {
			t.Errorf("parseHashAlgo(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

func generateTestCA(t *testing.T) ([]byte, []byte) {
	t.Helper()
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA private key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("failed to create CA certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		t.Fatalf("failed to marshal CA private key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM
}

func TestGenerateClientCert(t *testing.T) {
	caCertPEM, caKeyPEM := generateTestCA(t)

	tlsCert, err := generateClientCert(caCertPEM, caKeyPEM)
	if err != nil {
		t.Fatalf("generateClientCert() failed: %v", err)
	}

	if len(tlsCert.Certificate) != 1 {
		t.Fatalf("got %d certificates, want 1", len(tlsCert.Certificate))
	}
	if tlsCert.PrivateKey == nil {
		t.Fatal("got nil PrivateKey in tls.Certificate")
	}

	clientCert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatalf("failed to parse generated client certificate: %v", err)
	}

	if clientCert.Subject.CommonName != "attestz-client" {
		t.Errorf("CommonName = %q, want %q", clientCert.Subject.CommonName, "attestz-client")
	}

	hasClientAuth := false
	for _, usage := range clientCert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			hasClientAuth = true
			break
		}
	}
	if !hasClientAuth {
		t.Errorf("ExtKeyUsage does not contain ExtKeyUsageClientAuth: %v", clientCert.ExtKeyUsage)
	}

	caCertBlock, _ := pem.Decode(caCertPEM)
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		t.Fatalf("failed to parse test CA cert: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	opts := x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if _, err := clientCert.Verify(opts); err != nil {
		t.Errorf("clientCert.Verify() failed: %v", err)
	}
}

func TestGenerateClientCertErrors(t *testing.T) {
	caCertPEM, caKeyPEM := generateTestCA(t)

	if _, err := generateClientCert([]byte("invalid pem"), caKeyPEM); err == nil {
		t.Error("generateClientCert with invalid cert PEM succeeded, want error")
	}
	if _, err := generateClientCert(caCertPEM, []byte("invalid pem")); err == nil {
		t.Error("generateClientCert with invalid key PEM succeeded, want error")
	}
}

func TestParseExpectedPCRs(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    map[int][]byte
		wantErr bool
	}{
		{
			name:  "valid",
			input: `{"0":"010203","4":"040506"}`,
			want: map[int][]byte{
				0: {0x01, 0x02, 0x03},
				4: {0x04, 0x05, 0x06},
			},
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "empty json object",
			input:   "{}",
			wantErr: true,
		},
		{
			name:    "invalid json",
			input:   `not-json`,
			wantErr: true,
		},
		{
			name:    "non-numeric index",
			input:   `{"abc":"0102"}`,
			wantErr: true,
		},
		{
			name:    "invalid hex value",
			input:   `{"0":"not-hex"}`,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseExpectedPCRs(tc.input)
			if (err != nil) != tc.wantErr {
				t.Fatalf("parseExpectedPCRs(%q) error = %v, wantErr = %v", tc.input, err, tc.wantErr)
			}
			if !tc.wantErr {
				if diff := cmp.Diff(tc.want, got); diff != "" {
					t.Errorf("parseExpectedPCRs(%q) mismatch (-want +got):\n%s", tc.input, diff)
				}
			}
		})
	}
}

func TestCreateAttestRequestCustomIndices(t *testing.T) {
	req, err := createAttestRequest(cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA384, 1, 2, 3)
	if err != nil {
		t.Fatalf("createAttestRequest() failed: %v", err)
	}
	want := []int32{1, 2, 3}
	if diff := cmp.Diff(want, req.GetPcrIndices()); diff != "" {
		t.Errorf("PcrIndices mismatch (-want +got):\n%s", diff)
	}
}
