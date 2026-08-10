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

docker:
	docker build -t security-compliance-docs-collector .
	docker run --rm -p 8080:8080 security-compliance-docs-collector

test:
	go test ./...

fmt:
	gofmt -w .

vet:
	go vet ./...

.PHONY: run build collect collect-all refresh docker test fmt vet
