# This Makefile is meant to be used by people that do not usually work
# with Go source code. If you know what GOPATH is then you probably
# don't need to bother with make.

.PHONY: geth android ios geth-cross evm evmc all test clean

GOBIN = ./build/bin
GO ?= latest
GORUN = go run
ROOT_DIR := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

#? geth: Build geth
geth:
	$(GORUN) build/ci.go install ./cmd/geth
	@echo "Done building."
	@echo "Run \"$(GOBIN)/geth\" to launch geth."

#? all: Build all packages and executables
all:
	$(GORUN) build/ci.go install

#? test: Run the tests
test: all
	$(GORUN) build/ci.go test -timeout 20m

# The following commands acquire external EWASM and EVM interpreter shared objects for
# testing EVMC support.
hera:
	./build/hera.sh

evmone:
	./build/evmone.sh

# Test EVMC support against various external interpreters.
test-evmc: hera evmone
	go test -count 1 ./tests -run TestState -evmc.ewasm=$(ROOT_DIR)/build/_workspace/hera/build/src/libhera.so
	go test -count 1 ./tests -run TestState -evmc.evm=$(ROOT_DIR)/build/_workspace/evmone/lib/libevmone.so

clean-evmc:
	rm -rf ./build/_workspace/hera ./build/_workspace/evmone

#? lint: Run certain pre-selected linters
lint: ## Run linters.
	$(GORUN) build/ci.go lint

#? clean: Clean go cache, built executables, and the auto generated folder
clean:
	go clean -cache
	rm -fr build/_workspace/pkg/ $(GOBIN)/*

docs-generate: ## Generate JSON RPC API documentation from the OpenRPC service discovery document.
	env COREGETH_GEN_OPENRPC_DOCS=on go test -count=1 -run BuildStatic ./ethclient

# The devtools target installs tools required for 'go generate'.
# You need to put $GOBIN (or $GOPATH/bin) in your PATH to use 'go generate'.

#? devtools: Install recommended developer tools
devtools:
	env GOBIN= go install golang.org/x/tools/cmd/stringer@latest
	env GOBIN= go install github.com/fjl/gencodec@latest
	env GOBIN= go install github.com/golang/protobuf/protoc-gen-go@latest
	env GOBIN= go install ./cmd/abigen
	@type "solc" 2> /dev/null || echo 'Please install solc'
	@type "protoc" 2> /dev/null || echo 'Please install protoc'

#? help: Get more info on make commands.
help: Makefile
	@echo " Choose a command run in go-ethereum:"
	@sed -n 's/^#?//p' $< | column -t -s ':' |  sort | sed -e 's/^/ /'
.PHONY: help
