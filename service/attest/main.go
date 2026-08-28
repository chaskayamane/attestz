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
	"crypto/rand"
	"crypto/tls"
	"flag"
	"fmt"

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
	insecureConn = flag.Bool("insecure", true, "Use insecure transport credentials (without TLS)")
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

func main() {
	flag.Parse()
	ctx := context.Background()

	var transportOpt grpc.DialOption
	if *insecureConn {
		transportOpt = grpc.WithTransportCredentials(insecure.NewCredentials())
	} else {
		transportOpt = grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{}))
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
