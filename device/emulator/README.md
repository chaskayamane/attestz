# Enrollz and Attestz Device/Server Emulation

The code located in this directory is intended to emulate typical `enrollz`
and `attestz` gRPC servers that are hosted by the networking devices. Switch
owners are expected to implement Enrollz and Attestz Services that would
communicate to these switch-hosted gRPC endpoints to drive TPM 2.0 enrollment
and attestation workflows.

## Running

```bash
bazel run //device/emulator:device_emulator -- --alsologtostderr --ca_cert_out=/tmp/vendor_ca.pem
```

### Flags

- `--port`: Port to listen on (default: `4321`).
- `--ca_cert_out`: Optional path to write the vendor CA certificate PEM file. This certificate can be provided to the switch owner service emulator (`enrollz_emulator`) via `--vendor_ca_trust_bundle`.
- `--ca_cert`: Optional path to an existing vendor CA certificate PEM file.
- `--ca_key`: Optional path to an existing vendor CA private key PEM file.
- `--owner_ca_cert`: Optional path to switch owner CA certificate PEM file to verify client certificates in mTLS mode.
- `--insecure`: Use plaintext (insecure) connection instead of mTLS (default: `false`).
- `--alsologtostderr`: Logs output to stderr.

## End-to-End Example with Enrollz Service Emulator

1. Generate a test switch owner CA certificate and private key (used by `enrollz_emulator`):

   ```bash
   openssl ecparam -name secp384r1 -genkey -noout -out /tmp/owner_ca_key.pem
   openssl req -new -x509 -key /tmp/owner_ca_key.pem -out /tmp/owner_ca_cert.pem -days 365 -subj "/O=Switch Owner/CN=Switch Owner Root CA"
   ```

2. Start the device emulator and export its vendor CA certificate:

   ```bash
   bazel run //device/emulator:device_emulator -- --alsologtostderr --ca_cert_out=/tmp/vendor_ca.pem
   ```

   To enforce client certificate verification against the owner CA, pass `--owner_ca_cert=/tmp/owner_ca_cert.pem`.

3. In another terminal, run the switch owner Enrollz service emulator:

   ```bash
   bazel run //service/emulator:enrollz_emulator -- \
     --alsologtostderr \
     --vendor_ca_trust_bundle=/tmp/vendor_ca.pem \
     --owner_ca_cert=/tmp/owner_ca_cert.pem \
     --owner_ca_key=/tmp/owner_ca_key.pem
   ```
