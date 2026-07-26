BIN := bin/security-compliance-docs-collector

run:
	go run .

build:
	go build -o $(BIN) .

test:
	go test ./...

fmt:
	gofmt -w .

vet:
	go vet ./...

.PHONY: run build test fmt vet
