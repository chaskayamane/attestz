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

// Package main provides a client binary that calls the TpmAttestzService.Attest gRPC.
package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"time"

	log "github.com/golang/glog"
	cpb "github.com/openconfig/attestz/proto/common_definitions"
	apb "github.com/openconfig/attestz/proto/tpm_attestz"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/prototext"
)

var (
	addr         = flag.String("addr", "localhost:50051", "Address of the TpmAttestzService gRPC server")
	insecureConn = flag.Bool("insecure", false, "Use insecure transport credentials (without TLS)")
	ownerCACert  = flag.String("owner_ca_cert", "", "Path to the owner CA certificate file")
	ownerCAKey   = flag.String("owner_ca_key", "", "Path to the owner CA private key file")
)

// createAttestRequest constructs an AttestRequest for the active control card
// with a 32-byte random nonce, SHA256 hash algorithm, and PCR indices 0, 4, 7.
func createAttestRequest() (*apb.AttestRequest, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate random nonce: %w", err)
	}
	return &apb.AttestRequest{
		ControlCardSelection: &cpb.ControlCardSelection{
			ControlCardId: &cpb.ControlCardSelection_Role{
				Role: cpb.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE,
			},
		},
		Nonce:      nonce,
		HashAlgo:   cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA256,
		PcrIndices: []int32{0, 4, 7},
	}, nil
}

// attest calls the Attest RPC on the given client with the constructed request.
func attest(ctx context.Context, client apb.TpmAttestzServiceClient) (*apb.AttestResponse, error) {
	req, err := createAttestRequest()
	if err != nil {
		return nil, err
	}
	return client.Attest(ctx, req)
}

func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	return nil, errors.New("failed to parse private key (tried PKCS8, PKCS1, EC)")
}

// generateClientCert generates an ephemeral client key pair and issues a certificate signed by the CA.
func generateClientCert(caCertPEM, caKeyPEM []byte) (tls.Certificate, error) {
	var caCertBlock *pem.Block
	for rest := caCertPEM; len(rest) > 0; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			caCertBlock = block
			break
		}
	}
	if caCertBlock == nil {
		return tls.Certificate{}, errors.New("failed to find CERTIFICATE in CA cert PEM")
	}
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to parse CA cert: %w", err)
	}

	caKeyBlock, _ := pem.Decode(caKeyPEM)
	if caKeyBlock == nil {
		return tls.Certificate{}, errors.New("failed to decode CA key PEM")
	}
	caKey, err := parsePrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to parse CA key: %w", err)
	}

	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate client key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "attestz-client",
		},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to create client certificate: %w", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  clientKey,
	}, nil
}

func main() {
	flag.Parse()
	ctx := context.Background()

	var transportOpt grpc.DialOption
	if *insecureConn {
		transportOpt = grpc.WithTransportCredentials(insecure.NewCredentials())
	} else if *ownerCACert != "" && *ownerCAKey != "" {
		caCert, err := os.ReadFile(*ownerCACert)
		if err != nil {
			log.Exitf("Failed to read owner CA cert from %s: %v", *ownerCACert, err)
		}
		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(caCert) {
			log.Exitf("Failed to parse owner CA cert from %s", *ownerCACert)
		}
		caKey, err := os.ReadFile(*ownerCAKey)
		if err != nil {
			log.Exitf("Failed to read owner CA key from %s: %v", *ownerCAKey, err)
		}
		clientCert, err := generateClientCert(caCert, caKey)
		if err != nil {
			log.Exitf("Failed to generate client certificate: %v", err)
		}
		transportOpt = grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			RootCAs:            certPool,
			InsecureSkipVerify: true,
			Certificates:       []tls.Certificate{clientCert},
		}))
	} else {
		log.Exitf("No transport credentials specified. Use --insecure=true or --owner_ca_cert")
	}

	conn, err := grpc.NewClient(*addr, transportOpt)
	if err != nil {
		log.Exitf("Failed to create gRPC client for %s: %v", *addr, err)
	}
	defer conn.Close()

	client := apb.NewTpmAttestzServiceClient(conn)
	resp, err := attest(ctx, client)
	if err != nil {
		log.Exitf("Attest RPC failed: %v", err)
	}

	log.Infof("AttestResponse:\n%s", prototext.Format(resp))
}
