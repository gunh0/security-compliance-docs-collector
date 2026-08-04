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

### Collecting Documents

`cmd/collect` checks the upstream catalog for CIS benchmark versions that are not in `docs/` yet, validates them (framework, provider, version, requirements) and stores them. Existing documents are never overwritten.

```sh
make collect        # latest version per provider
make collect-all    # every published version
go run ./cmd/collect -ref <tag-or-commit>   # pin the upstream revision
```

Set `GITHUB_TOKEN` (or put it in `.env`, see `.env.template`) to raise the GitHub API rate limit.

### Collected Documents

| Provider | CIS Benchmark versions |
|---|---|
| AWS | v1.4.0, v3.0.0, v7.0.0 |
| Azure | v2.0.0, v2.1.0, v6.0.0 |
| GCP | v2.0.0, v5.0.0 |
| Kubernetes | v1.8.0, v2.0.1 |

### Project Structure

```
.
├── main.go                  # entrypoint: flags, http.Server
├── cmd/collect/             # collects new benchmark versions into docs/
├── docs/                    # compliance documents grouped by provider
└── internal/
    ├── catalog/             # builds the document tree, reads documents safely
    ├── collector/           # lists, validates and stores upstream documents
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

### Data Source

The compliance documents in `docs/` are collected from the compliance catalog of [Prowler](https://github.com/prowler-cloud/prowler/tree/master/prowler/compliance) (Apache License 2.0), which maps CIS Benchmark requirements to automated checks. CIS Benchmarks are © Center for Internet Security, Inc.

### License

This project is licensed under the Apache License 2.0
