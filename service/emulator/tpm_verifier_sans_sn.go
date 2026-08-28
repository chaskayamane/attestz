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
	"fmt"

	log "github.com/golang/glog"
	"github.com/openconfig/attestz/service/biz"
)

// tpmCertVerifierSansSN is a TpmCertVerifier implementation that does not check for an IAK serial number.
type tpmCertVerifierSansSN struct{}

// VerifyIakAndIDevIDCerts verifies IAK and IDevID certs without checking for subject serial numbers.
func (tcv *tpmCertVerifierSansSN) VerifyIakAndIDevIDCerts(ctx context.Context, req *biz.VerifyIakAndIDevIDCertsReq) (*biz.VerifyIakAndIDevIDCertsResp, error) {
	if req == nil {
		err := fmt.Errorf("request VerifyIakAndIDevIDCertsReq is nil")
		log.ErrorContext(ctx, err)
		return nil, err
	}
	if req.ControlCardID == nil {
		err := fmt.Errorf("field ControlCardID in VerifyIakAndIDevIDCertsReq request is nil")
		log.ErrorContext(ctx, err)
		return nil, err
	}
	iakX509, err := biz.VerifyAndParsePemCert(ctx, req.IakCertPem, req.CertVerificationOpts)
	if err != nil {
		err = fmt.Errorf("failed to verify and parse IAK cert: %w", err)
		log.ErrorContext(ctx, err)
		return nil, err
	}
	log.InfoContext(ctx, "Successfully verified and parsed IAK cert")

	// Verify and convert IAK certs' pub keys to PEM.
	iakPubPem, err := biz.VerifyAndSerializePubKey(ctx, iakX509)
	if err != nil {
		err = fmt.Errorf("failed to verify and serialize IAK pub key: %w", err)
		log.ErrorContext(ctx, err)
		return nil, err
	}
	log.InfoContextf(ctx, "Successfully verified and parsed IAK pub key PEM %s", iakPubPem)

	// IDevID cert is needed on the primary control card. On the secondary
	// it is only needed if no direct communication to the primary control card
	// is possible.
	if req.IDevIDCertPem == "" {
		return &biz.VerifyIakAndIDevIDCertsResp{
			IakPubPem: iakPubPem,
		}, nil
	}

	iDevIDX509, err := biz.VerifyAndParsePemCert(ctx, req.IDevIDCertPem, req.CertVerificationOpts)
	if err != nil {
		err = fmt.Errorf("failed to verify and parse IDevID cert: %w", err)
		log.ErrorContext(ctx, err)
		return nil, err
	}
	log.InfoContext(ctx, "Successfully verified and parsed IDevID cert")

	// Verify and convert IDevID certs' pub keys to PEM.
	iDevIDPubPem, err := biz.VerifyAndSerializePubKey(ctx, iDevIDX509)
	if err != nil {
		err = fmt.Errorf("failed to verify and serialize IDevID pub key: %w", err)
		log.ErrorContext(ctx, err)
		return nil, err
	}
	log.InfoContextf(ctx, "Successfully verified and parsed IDevID pub key PEM %s", iDevIDPubPem)

	return &biz.VerifyIakAndIDevIDCertsResp{
		IakPubPem:    iakPubPem,
		IDevIDPubPem: iDevIDPubPem,
	}, nil
}

// VerifyTpmCert verifies a TPM cert without checking for subject serial numbers.
func (tcv *tpmCertVerifierSansSN) VerifyTpmCert(ctx context.Context, req *biz.VerifyTpmCertReq) (*biz.VerifyTpmCertResp, error) {
	if req == nil {
		err := fmt.Errorf("request VerifyTpmCertReq is nil")
		log.ErrorContext(ctx, err)
		return nil, err
	}
	if req.ControlCardID == nil {
		err := fmt.Errorf("field ControlCardID in VerifyTpmCertReq request is nil")
		log.ErrorContext(ctx, err)
		return nil, err
	}
	certX509, err := biz.VerifyAndParsePemCert(ctx, req.CertPem, req.CertVerificationOpts)
	if err != nil {
		err = fmt.Errorf("failed to verify and parse PEM cert: %w", err)
		log.ErrorContext(ctx, err)
		return nil, err
	}
	log.InfoContext(ctx, "Successfully verified and parsed PEM cert into x509 structure")

	// Verify and convert x509 cert pub key to PEM.
	pubKeyPem, err := biz.VerifyAndSerializePubKey(ctx, certX509)
	if err != nil {
		err = fmt.Errorf("failed to verify and serialize cert's pub key: %w", err)
		log.ErrorContext(ctx, err)
		return nil, err
	}
	log.InfoContextf(ctx, "Successfully verified and parsed pub key PEM %s", pubKeyPem)

	return &biz.VerifyTpmCertResp{
		PubPem: pubKeyPem,
	}, nil
}
