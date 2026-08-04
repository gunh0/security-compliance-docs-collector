// Package collector fetches CIS benchmark documents published in the
// Prowler compliance catalog and stores them in the docs directory.
package collector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const maxDocumentSize = 16 << 20

// Provider is a cloud or platform whose CIS benchmarks are collected.
type Provider struct {
	Name       string // directory name, e.g. "aws"
	Label      string // value of the document's Provider field, e.g. "AWS"
	FilePrefix string // local file name prefix
}

// Providers lists the providers kept in the docs directory.
var Providers = []Provider{
	{"aws", "AWS", "cis_amazon_web_services_foundations_benchmark"},
	{"azure", "Azure", "cis_microsoft_azure_foundations_benchmark"},
	{"gcp", "GCP", "cis_google_cloud_platform_foundation_benchmark"},
	{"kubernetes", "Kubernetes", "cis_kubernetes_benchmark"},
}

// Source is a GitHub repository directory holding compliance documents,
// one sub-directory per provider.
type Source struct {
	APIBase string // e.g. https://api.github.com
	Repo    string // owner/name
	Ref     string // branch, tag or commit
	Dir     string // path of the compliance directory in the repository
	Token   string // optional GitHub token to raise the API rate limit
	Client  *http.Client
}

// Prowler returns the upstream source of the documents in this repository.
func Prowler() *Source {
	return &Source{
		APIBase: "https://api.github.com",
		Repo:    "prowler-cloud/prowler",
		Ref:     "master",
		Dir:     "prowler/compliance",
		Client:  http.DefaultClient,
	}
}

// Benchmark is one version of a provider's CIS benchmark in the source.
type Benchmark struct {
	Provider    Provider
	Version     Version
	DownloadURL string
}

// FileName is the local file name of the benchmark.
func (b Benchmark) FileName() string {
	return fmt.Sprintf("%s_v%s.json", b.Provider.FilePrefix, b.Version)
}

// List returns the CIS benchmarks of p in the source, oldest first.
func (s *Source) List(ctx context.Context, p Provider) ([]Benchmark, error) {
	url := fmt.Sprintf("%s/repos/%s/contents/%s/%s?ref=%s", s.APIBase, s.Repo, s.Dir, p.Name, s.Ref)
	body, err := s.get(ctx, url, "application/vnd.github+json")
	if err != nil {
		return nil, err
	}

	var entries []struct {
		Name        string `json:"name"`
		Type        string `json:"type"`
		DownloadURL string `json:"download_url"`
	}
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("list %s: %w", p.Name, err)
	}

	pattern := regexp.MustCompile(`^cis_(\d+(?:\.\d+)*)_` + regexp.QuoteMeta(p.Name) + `\.json$`)
	var benchmarks []Benchmark
	for _, e := range entries {
		m := pattern.FindStringSubmatch(e.Name)
		if e.Type != "file" || m == nil {
			continue
		}
		v, err := ParseVersion(m[1])
		if err != nil {
			return nil, err
		}
		benchmarks = append(benchmarks, Benchmark{Provider: p, Version: v, DownloadURL: e.DownloadURL})
	}

	sort.Slice(benchmarks, func(i, j int) bool { return benchmarks[i].Version.Less(benchmarks[j].Version) })
	return benchmarks, nil
}

// Fetch downloads b, checks that it is the expected CIS document and returns
// it indented with four spaces, like the rest of the docs directory.
func (s *Source) Fetch(ctx context.Context, b Benchmark) ([]byte, error) {
	body, err := s.get(ctx, b.DownloadURL, "")
	if err != nil {
		return nil, err
	}

	var doc struct {
		Framework    string
		Provider     string
		Version      string
		Requirements []json.RawMessage
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", b.FileName(), err)
	}
	v, err := ParseVersion(doc.Version)
	switch {
	case doc.Framework != "CIS":
		return nil, fmt.Errorf("%s: framework is %q, want CIS", b.FileName(), doc.Framework)
	case !strings.EqualFold(doc.Provider, b.Provider.Label):
		return nil, fmt.Errorf("%s: provider is %q, want %s", b.FileName(), doc.Provider, b.Provider.Label)
	case err != nil || v.Compare(b.Version) != 0:
		return nil, fmt.Errorf("%s: document version is %q", b.FileName(), doc.Version)
	case len(doc.Requirements) == 0:
		return nil, fmt.Errorf("%s: no requirements", b.FileName())
	}

	var out bytes.Buffer
	if err := json.Indent(&out, body, "", "    "); err != nil {
		return nil, err
	}
	out.WriteByte('\n')
	return out.Bytes(), nil
}

// Result reports what Sync did with one benchmark.
type Result struct {
	Path  string
	Added bool // false if the file already existed
}

// Sync stores the benchmarks of each provider under docsDir/<provider>/.
// Only the latest version is collected unless all is set. Existing files
// are left untouched.
func Sync(ctx context.Context, s *Source, docsDir string, providers []Provider, all bool) ([]Result, error) {
	var results []Result
	for _, p := range providers {
		benchmarks, err := s.List(ctx, p)
		if err != nil {
			return results, err
		}
		if len(benchmarks) == 0 {
			return results, fmt.Errorf("no CIS benchmarks found for %s", p.Name)
		}
		if !all {
			benchmarks = benchmarks[len(benchmarks)-1:]
		}

		for _, b := range benchmarks {
			path := filepath.Join(docsDir, p.Name, b.FileName())
			if _, err := os.Stat(path); err == nil {
				results = append(results, Result{Path: path})
				continue
			} else if !errors.Is(err, os.ErrNotExist) {
				return results, err
			}

			data, err := s.Fetch(ctx, b)
			if err != nil {
				return results, err
			}
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return results, err
			}
			if err := os.WriteFile(path, data, 0o644); err != nil {
				return results, err
			}
			results = append(results, Result{Path: path, Added: true})
		}
	}
	return results, nil
}

func (s *Source) get(ctx context.Context, url, accept string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	if s.Token != "" {
		req.Header.Set("Authorization", "Bearer "+s.Token)
	}

	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDocumentSize+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxDocumentSize {
		return nil, fmt.Errorf("GET %s: response larger than %d bytes", url, maxDocumentSize)
	}
	return body, nil
}

// Version is a benchmark version normalized to major.minor.patch.
type Version [3]int

// ParseVersion parses versions such as "3.0", "1.10" or "2.0.1".
func ParseVersion(s string) (Version, error) {
	var v Version
	parts := strings.Split(s, ".")
	if len(parts) == 0 || len(parts) > 3 {
		return v, fmt.Errorf("invalid version %q", s)
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return v, fmt.Errorf("invalid version %q", s)
		}
		v[i] = n
	}
	return v, nil
}

func (v Version) String() string { return fmt.Sprintf("%d.%d.%d", v[0], v[1], v[2]) }

// Compare returns -1, 0 or +1 depending on whether v is older than, equal
// to or newer than w.
func (v Version) Compare(w Version) int {
	for i := range v {
		if v[i] != w[i] {
			if v[i] < w[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// Less reports whether v is older than w.
func (v Version) Less(w Version) bool { return v.Compare(w) < 0 }
