BIN := bin/security-compliance-docs-collector

-include .env
export GITHUB_TOKEN

run:
	go run .

build:
	go build -o $(BIN) .

collect:
	go run ./cmd/collect

collect-all:
	go run ./cmd/collect -all

refresh:
	go run ./cmd/collect -all -refresh

test:
	go test ./...

fmt:
	gofmt -w .

vet:
	go vet ./...

.PHONY: run build collect collect-all refresh test fmt vet
