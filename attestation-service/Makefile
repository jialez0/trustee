build:
	@echo "build CoCo-AS (gRPC and RESTful)"
	cd attestation-service && make build
	@echo build RVPS and client tool
	cd rvps && make build

install:
	@echo "install CoCo-AS (gRPC and RESTful)"
	cd attestation-service && make install
	@echo install RVPS and client tool
	cd rvps && make install

clean:
	cargo clean
