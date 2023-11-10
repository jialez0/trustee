PREFIX := /usr/local

TARGET_DIR := ../../target/release
DESTDIR ?= $(PREFIX)/bin
BIN_NAMES := as-grpc as-restful

build: grpc restful

# Build CoCo-AS in gRPC version
grpc:
	cargo build --release --bin as-grpc --no-default-features --features rvps-grpc,all-verifier,grpc-bin

# Build CoCo-AS in RESTful version
restful:
	cargo build --release --bin as-restful --no-default-features --features rvps-grpc,all-verifier,restful-bin

install:
	for bin_name in $(BIN_NAMES); do \
		install -D -m0755 $(TARGET_DIR)/$$bin_name $(DESTDIR); \
	done

clean:
	cargo clean