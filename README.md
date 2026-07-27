# Security Compliance Docs Collector

This tool collects and displays security compliance documents from various cloud providers.
It provides an easy-to-use interface for viewing the contents of these documents.

### Environment

- Go 1.24+ (standard library only, no external dependencies)

### Installation

```sh
git clone https://github.com/gunh0/security-compliance-docs-collector.git
cd security-compliance-docs-collector
make build   # -> bin/security-compliance-docs-collector
```

### Usage

1. Start the server:

```sh
make run
# or, with a custom address / docs directory
go run . -addr 127.0.0.1:9000 -docs ./docs
```

2. Open a web browser and navigate to <http://localhost:8080>.

3. Browse the list of available compliance documents and click on any document to view its contents.

| Flag | Default | Description |
|---|---|---|
| `-addr` | `127.0.0.1:8080` | Listen address |
| `-docs` | `docs` | Directory containing compliance documents (`<provider>/<benchmark>.json`) |

### Project Structure

```
.
├── main.go                  # entrypoint: flags, http.Server
├── docs/                    # compliance documents grouped by provider
└── internal/
    ├── catalog/             # builds the document tree, reads documents safely
    └── web/                 # HTTP handlers + embedded templates/static assets
```

### Development

```sh
make test   # go test ./...
make vet    # go vet ./...
make fmt    # gofmt -w .
```

### Features

- Display a list of security compliance documents organized by cloud provider
- View the contents of JSON-formatted compliance documents in an interactive tree structure
- Easy navigation between document list and individual document views
- Document access is confined to the docs directory (`os.Root`), so path traversal requests are rejected
- Single static binary with templates and assets embedded

### License

This project is licensed under the Apache License 2.0
