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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	cpb "github.com/openconfig/attestz/proto/common_definitions"
	apb "github.com/openconfig/attestz/proto/tpm_attestz"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestCreateAttestRequest(t *testing.T) {
	req1, err := createAttestRequest()
	if err != nil {
		t.Fatalf("createAttestRequest() failed: %v", err)
	}

	// Verify ControlCardSelection role is ACTIVE.
	role := req1.GetControlCardSelection().GetRole()
	if role != cpb.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE {
		t.Errorf("ControlCardSelection role = %v, want %v", role, cpb.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE)
	}

	// Verify Nonce is 32 bytes.
	if len(req1.GetNonce()) != 32 {
		t.Errorf("Nonce length = %d, want 32", len(req1.GetNonce()))
	}

	// Verify HashAlgo is TPM_2_0_HASH_ALGO_SHA256.
	if req1.GetHashAlgo() != cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA256 {
		t.Errorf("HashAlgo = %v, want %v", req1.GetHashAlgo(), cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA256)
	}

	// Verify PcrIndices are [0, 4, 7].
	wantPcr := []int32{0, 4, 7}
	if diff := cmp.Diff(wantPcr, req1.GetPcrIndices()); diff != "" {
		t.Errorf("PcrIndices mismatch (-want +got):\n%s", diff)
	}

	// Verify Nonce is random by checking that successive calls produce different nonces.
	req2, err := createAttestRequest()
	if err != nil {
		t.Fatalf("second createAttestRequest() failed: %v", err)
	}
	if bytes.Equal(req1.GetNonce(), req2.GetNonce()) {
		t.Errorf("Nonces are identical across calls: %x", req1.GetNonce())
	}
}

type fakeAttestServer struct {
	apb.UnimplementedTpmAttestzServiceServer
	receivedReq *apb.AttestRequest
	resp        *apb.AttestResponse
	err         error
}

func (s *fakeAttestServer) Attest(ctx context.Context, req *apb.AttestRequest) (*apb.AttestResponse, error) {
	s.receivedReq = req
	return s.resp, s.err
}

func setupTestServer(t *testing.T, srv *fakeAttestServer) apb.TpmAttestzServiceClient {
	t.Helper()
	lis := bufconn.Listen(1024 * 1024)
	s := grpc.NewServer()
	apb.RegisterTpmAttestzServiceServer(s, srv)

	go func() {
		if err := s.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			t.Errorf("Server exited with error: %v", err)
		}
	}()
	t.Cleanup(func() {
		s.Stop()
		lis.Close()
	})

	conn, err := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("Failed to create client connection: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	return apb.NewTpmAttestzServiceClient(conn)
}

func TestAttestSuccess(t *testing.T) {
	wantResp := &apb.AttestResponse{
		ControlCardId: &cpb.ControlCardVendorId{
			ControlCardRole:   cpb.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE,
			ControlCardSerial: "test-card-123",
		},
		Format: apb.AttestResponse_ATTESTATION_FORMAT_TPM_RAW,
	}
	server := &fakeAttestServer{resp: wantResp}
	client := setupTestServer(t, server)

	gotResp, err := attest(context.Background(), client)
	if err != nil {
		t.Fatalf("attest() failed: %v", err)
	}

	if diff := cmp.Diff(wantResp, gotResp, protocmp.Transform()); diff != "" {
		t.Errorf("attest() response mismatch (-want +got):\n%s", diff)
	}

	// Verify the request received by the server.
	req := server.receivedReq
	if req == nil {
		t.Fatal("server did not receive any request")
	}
	if req.GetControlCardSelection().GetRole() != cpb.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE {
		t.Errorf("received role = %v, want %v", req.GetControlCardSelection().GetRole(), cpb.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE)
	}
	if len(req.GetNonce()) != 32 {
		t.Errorf("received nonce length = %d, want 32", len(req.GetNonce()))
	}
	if req.GetHashAlgo() != cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA256 {
		t.Errorf("received hash_algo = %v, want %v", req.GetHashAlgo(), cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA256)
	}
	if diff := cmp.Diff([]int32{0, 4, 7}, req.GetPcrIndices()); diff != "" {
		t.Errorf("received pcr_indices mismatch (-want +got):\n%s", diff)
	}
}

func TestAttestError(t *testing.T) {
	wantErr := errors.New("rpc error: code = Unavailable desc = device unreachable")
	server := &fakeAttestServer{err: wantErr}
	client := setupTestServer(t, server)

	_, err := attest(context.Background(), client)
	if err == nil {
		t.Fatal("attest() succeeded unexpectedly, want error")
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

