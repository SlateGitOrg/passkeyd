# passkeyd - every quality gate behind one target: `make check`.
GO            ?= go
GOLANGCI_LINT ?= golangci-lint
COVER_MIN     ?= 80
FUZZTIME      ?= 30s
export GOFLAGS ?= -p=3

.PHONY: check fmt-check vet lint test cover demo bench fuzz build run vectors clean

check: fmt-check vet lint test cover ## format-check + vet/type-check + lint + race tests + coverage gate

fmt-check: ## fail if any Go file is not gofmt-formatted
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

vet: ## compile everything (type-check) and run go vet
	$(GO) build ./...
	$(GO) vet ./...

lint: ## golangci-lint with zero warnings
	$(GOLANGCI_LINT) run ./...

test: ## unit + integration tests (fuzz seed corpora included) under the race detector
	$(GO) test -race -count=1 ./...

cover: ## core-package statement coverage, fails below COVER_MIN
	./scripts/coverage.sh $(COVER_MIN)

demo: ## offline end-to-end demo against bundled fixtures
	$(GO) run ./cmd/passkeyd demo

bench: ## micro-benchmarks for CBOR, ceremonies and the challenge store
	$(GO) test -run='^$$' -bench=. -benchmem ./cbor/ ./challenge/ ./webauthn/

fuzz: ## run every fuzz target for FUZZTIME each
	$(GO) test -run='^$$' -fuzz='^FuzzDecode$$' -fuzztime=$(FUZZTIME) ./cbor/
	$(GO) test -run='^$$' -fuzz='^FuzzParseKey$$' -fuzztime=$(FUZZTIME) ./cose/
	$(GO) test -run='^$$' -fuzz='^FuzzParseAuthenticatorData$$' -fuzztime=$(FUZZTIME) ./webauthn/
	$(GO) test -run='^$$' -fuzz='^FuzzFinishRegistration$$' -fuzztime=$(FUZZTIME) ./webauthn/

build: ## build the passkeyd binary into bin/
	$(GO) build -trimpath -o bin/passkeyd ./cmd/passkeyd

run: build ## serve the browser demo on http://localhost:8080
	./bin/passkeyd serve

vectors: ## re-extract spec vectors from a downloaded WebAuthn spec (SPEC=path/to/index.html)
	python3 scripts/extract_vectors.py $(SPEC) > testdata/webauthn-l3-vectors.json

clean:
	rm -rf bin coverage.out
