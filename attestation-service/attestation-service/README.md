# CoCo Attestation Service

CoCo Attestation Service provides two versions, s.t. based on gRPC protocol and RESTful.

## Build

Build and install:
```shell
git clone https://github.com/confidential-containers/kbs
cd kbs/attestation-service/attestation-service
WORKDIR=$(pwd)
make build && make install
```

Or, we can build the docker image
```shell
cd ../..
# Build grpc version of CoCo-AS image
docker build -t attestation-service:grpc -f attestation-service/Dockerfile.as .

# Build RESTful version of CoCo-AS image
docker build -t attestation-service:restful -f attestation-service/Dockerfile.restful .
```

## Usage

### gRPC CoCo-AS

#### Run
We can directly use a container image to run
```shell
docker run -d \
    -v /etc/sgx_default_qcnl.conf:/etc/sgx_default_qcnl.conf \
    -p 50004
    attestation-service:grpc
```

Or, we can use the installed binary.

- For help information, run:
```shell
as-grpc --help
```

- For version information, run:
```shell
as-grpc --version
```

Start Attestation Service and specify the listen port of its gRPC service:
```shell
as-grpc --config-file config.json --socket 127.0.0.1:50004
```

If you want to see the runtime log, run:
```shell
RUST_LOG=debug as-grpc --config-file config.json --socket 127.0.0.1:50004
```

#### API

gRPC CoCo-AS provides gRPC endpoints which is defined in [proto](../protos/attestation.proto).

#### Test

For example, we can use an SGX evidence to test CoCo-AS (gRPC).

```shell
# Use the following cmdline to install grpcurl
# go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest

cd $WORKDIR

REQ=$(cat test-data/grpc-request.json)

grpcurl -plaintext -import-path protos -proto ../attestation.proto -d @ 127.0.0.1:50004 attestation.AttestationService/AttestationEvaluate <<EOF
$REQ
EOF
```

### RESTful CoCo-AS

#### Run
We can directly use the docker image to run

```shell
docker run -d \
    -v /etc/sgx_default_qcnl.conf:/etc/sgx_default_qcnl.conf \
    -p 50004
    attestation-service:restful
```

Or, run using the installed binary
```shell
as-restful --config-file config.json --socket 127.0.0.1:50004
```

- For help information, run:
```shell
as-restful --help
```

#### API

RESTful CoCo-AS's endpoints are as following:
- `/attestation`: receives evidence verification request. The request POST payload is like
```json
{
    "tee": "sgx", // tee type. like sgx, tdx, snp, etc.
    "evidence": "YWFhCg==...", // base64 encoded evidence,
    "runtime_data": ["YWFhCg==...", "YWFhCg==..."], // base64 encoded materials that used to calculate the
                                                    // digest inside report_data to check the binding.
                                                    // If sets [] the comparation will be skipped.
    "init_data": ["YWFhCg==...", "YWFhCg==..."],    // base64 encoded materials that used to calculate the
                                                    // digest inside initdata digest to check the binding.
                                                    // If sets [] the comparation will be skipped.
    "policy_ids": ["default", "policy-1"]           // policies used to check against the evidence.
}
```
- `/set_policy`: receives policy setting request. The request POST payload is like
```json
{
    "type": "rego",         // policy type
    "policy_id": "yyyyy",   // raw string of policy id
    "policy": "xxxxx"       // base64 encoded policy content
}
```

#### Test

For example, we can use an SGX evidence to test CoCo-AS (RESTful)

```shell
cd $WORKDIR

curl -k -X POST http://127.0.0.1:50004/attestation \
     -i \
     -H 'Content-Type: application/json' \
     -d @test-data/restful-request.json
```