# Enrollz and Attestz _(Switch Owner)_ Services Emulation

The code located in this directory is intended to emulate typical Enrollz
and Attestz Services hosted by a switch owner. These services will
communicate with the networking devices hosting gRPC `enrollz` and
`attestz` endpoints and drive TPM 2.0 enrollment and attestation workflows.

## Running

You can run the Enrollz service emulator using `bazel run`:

> [!NOTE]
> The `--vendor_ca_trust_bundle` flag is required. When testing with the device emulator, pass the path to the certificate exported via the device emulator's `--ca_cert_out` flag.

```bash
bazel run //service/emulator:enrollz_emulator -- \
  --alsologtostderr \
  --vendor_ca_trust_bundle=/tmp/vendor_ca.pem
```

### Flags

- `--vendor_ca_trust_bundle`: Path to switch vendor CA trust bundle PEM file (required).
- `--client_ip`: IP address or `host:port` of the client device (default: `127.0.0.1`, default port: `4321`).
- `--owner_ca_cert`: Path to switch owner CA certificate PEM file (default: `service/emulator/owner_ca_cert.pem`).
- `--owner_ca_key`: Path to switch owner CA private key PEM file (default: `service/emulator/owner_ca_key.pem`).
- `--insecure`: Use plaintext (insecure) gRPC connection instead of TLS (default: `false`).
- `--alsologtostderr`: Logs output to stderr.

## End-to-End Example with Device Emulator

1. Start the device emulator and export its vendor CA certificate:

   ```bash
   bazel run //device/emulator:device_emulator -- --alsologtostderr --ca_cert_out=/tmp/vendor_ca.pem
   ```

2. In another terminal, run the switch owner Enrollz service emulator:
   ```bash
   bazel run //service/emulator:enrollz_emulator -- --alsologtostderr --vendor_ca_trust_bundle=/tmp/vendor_ca.pem
   ```

The servive/emulator folder contains an owner CA certificate and key for testing purposes.
Since the key is public, it should not be used in production or considered to be secure.

## Container

To load and run the emulator as a container:

```bash
bazel run //service/emulator:load_enrollz_emulator_image

docker run --rm --network=host -v /tmp/:/tmp/ open-config-enrollz-emulator:latest \
  --alsologtostderr \
  --vendor_ca_trust_bundle=/tmp/vendor_ca.pem
```

The image can then be passed and run on other hosts:

```bash
<user>@<host_origin>:~$ docker save --output open_config_enrollz_emulator.tar open-config-enrollz-emulator:latest

<user>@<host_origin>:~$ scp open_config_enrollz_emulator.tar <user>@<host_destination>:~

<user>@<host_destination>:~$ docker load --input open_config_enrollz_emulator.tar
```
