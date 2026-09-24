// Package collector fetches compliance documents (CIS benchmarks and other
// frameworks) published in the Prowler compliance catalog and stores them in
// the docs directory.
package collector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gunh0/security-compliance-docs-collector/internal/manifest"
)

const maxDocumentSize = 16 << 20

// ErrNotPublished is returned for documents that do not exist in the source.
var ErrNotPublished = errors.New("document not published")

// Provider is a cloud or platform whose documents are collected.
type Provider struct {
	Name       string // directory name, e.g. "aws"
	Label      string // value of the document's Provider field, e.g. "AWS"
	FilePrefix string // local file name prefix of CIS benchmarks; empty if none are collected
}

// Providers lists the providers kept in the docs directory.
var Providers = []Provider{
	{"aws", "AWS", "cis_amazon_web_services_foundations_benchmark"},
	{"azure", "Azure", "cis_microsoft_azure_foundations_benchmark"},
	{"gcp", "GCP", "cis_google_cloud_platform_foundation_benchmark"},
	{"kubernetes", "Kubernetes", "cis_kubernetes_benchmark"},
	{"oraclecloud", "OracleCloud", "cis_oracle_cloud_infrastructure_foundations_benchmark"},
	{"alibabacloud", "AlibabaCloud", "cis_alibaba_cloud_foundations_benchmark"},
	{"nhn", "NHN", ""},
}

// Standard is a non-CIS framework published under the same file name for
// each provider, e.g. iso27001_2022_aws.json.
type Standard struct {
	Name      string   // upstream file name without the provider suffix
	Framework string   // expected Framework field
	Providers []string // provider directory names
}

// Standards lists the non-CIS frameworks kept in the docs directory.
var Standards = []Standard{
	{"iso27001_2022", "ISO27001", []string{"aws", "azure", "gcp", "kubernetes", "nhn"}},
	{"kisa_isms_p_2023_korean", "KISA-ISMS-P", []string{"aws"}},
	{"nist_800_53_revision_5", "NIST-800-53-Revision-5", []string{"aws"}},
	{"nist_csf_2.0", "NIST-CSF", []string{"aws"}},
	{"aws_foundational_security_best_practices", "AWS-Foundational-Security-Best-Practices", []string{"aws"}},
	{"aws_well_architected_framework_security_pillar", "AWS-Well-Architected-Framework-Security-Pillar", []string{"aws"}},
	{"soc2", "SOC2", []string{"aws", "azure", "gcp"}},
	{"mitre_attack", "MITRE-ATTACK", []string{"aws", "azure", "gcp"}},
}

// Source is a GitHub repository directory holding compliance documents,
// one sub-directory per provider.
type Source struct {
	APIBase string // e.g. https://api.github.com
	RawBase string // e.g. https://raw.githubusercontent.com
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
		RawBase: "https://raw.githubusercontent.com",
		Repo:    "prowler-cloud/prowler",
		Ref:     "master",
		Dir:     "prowler/compliance",
		Client:  http.DefaultClient,
	}
}

// Document is a provider's compliance document in the source.
type Document struct {
	Provider  Provider
	Framework string  // expected Framework field, e.g. "CIS"
	Version   Version // CIS benchmarks only
	Name      string  // local file name without extension; empty for CIS benchmarks
	Path      string  // path of the document in the source repository
}

// FileName is the local file name of the document.
func (b Document) FileName() string {
	if b.Name != "" {
		return b.Name + ".json"
	}
	return fmt.Sprintf("%s_v%s.json", b.Provider.FilePrefix, b.Version)
}

// LocalPath is the slash-separated path of the document in the docs root.
func (b Document) LocalPath() string {
	return b.Provider.Name + "/" + b.FileName()
}

// Standards returns the non-CIS documents of p in the source.
func (s *Source) Standards(p Provider) []Document {
	var docs []Document
	for _, st := range Standards {
		for _, name := range st.Providers {
			if name == p.Name {
				docs = append(docs, Document{
					Provider:  p,
					Framework: st.Framework,
					Name:      st.Name,
					Path:      fmt.Sprintf("%s/%s/%s_%s.json", s.Dir, p.Name, st.Name, p.Name),
				})
			}
		}
	}
	return docs
}

// Revision is the upstream commit that last changed a document.
type Revision struct {
	SHA  string
	Date time.Time
}

// List returns the CIS benchmarks of p in the source, oldest first.
func (s *Source) List(ctx context.Context, p Provider) ([]Document, error) {
	dir := s.Dir + "/" + p.Name
	u := fmt.Sprintf("%s/repos/%s/contents/%s?ref=%s", s.APIBase, s.Repo, dir, url.QueryEscape(s.Ref))
	body, err := s.get(ctx, u, "application/vnd.github+json")
	if err != nil {
		return nil, err
	}

	var entries []struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("list %s: %w", p.Name, err)
	}

	pattern := regexp.MustCompile(`^cis_(\d+(?:\.\d+)*)_` + regexp.QuoteMeta(p.Name) + `\.json$`)
	var benchmarks []Document
	for _, e := range entries {
		m := pattern.FindStringSubmatch(e.Name)
		if e.Type != "file" || m == nil {
			continue
		}
		v, err := ParseVersion(m[1])
		if err != nil {
			return nil, err
		}
		benchmarks = append(benchmarks, Document{Provider: p, Framework: "CIS", Version: v, Path: dir + "/" + e.Name})
	}

	sort.Slice(benchmarks, func(i, j int) bool { return benchmarks[i].Version.Less(benchmarks[j].Version) })
	return benchmarks, nil
}

// Revision returns the latest commit, reachable from the source ref, that
// changed b.
func (s *Source) Revision(ctx context.Context, b Document) (Revision, error) {
	u := fmt.Sprintf("%s/repos/%s/commits?path=%s&sha=%s&per_page=1",
		s.APIBase, s.Repo, url.QueryEscape(b.Path), url.QueryEscape(s.Ref))
	body, err := s.get(ctx, u, "application/vnd.github+json")
	if err != nil {
		return Revision{}, err
	}

	var commits []struct {
		SHA    string `json:"sha"`
		Commit struct {
			Committer struct {
				Date time.Time `json:"date"`
			} `json:"committer"`
		} `json:"commit"`
	}
	if err := json.Unmarshal(body, &commits); err != nil {
		return Revision{}, fmt.Errorf("history of %s: %w", b.Path, err)
	}
	if len(commits) == 0 {
		return Revision{}, fmt.Errorf("%s: %w", b.Path, ErrNotPublished)
	}
	return Revision{SHA: commits[0].SHA, Date: commits[0].Commit.Committer.Date}, nil
}

// SourceURL links to b as of rev.
func (s *Source) SourceURL(b Document, rev Revision) string {
	return fmt.Sprintf("https://github.com/%s/blob/%s/%s", s.Repo, rev.SHA, b.Path)
}

// Fetch downloads b as of rev, checks that it is the expected document and
// returns it indented with four spaces, like the rest of the docs directory.
// For CIS benchmarks it also returns the version stated in the document,
// which may be more precise than the file name, e.g. 4.0.1 in cis_4.0_aws.json.
func (s *Source) Fetch(ctx context.Context, b Document, rev Revision) ([]byte, Version, error) {
	body, err := s.get(ctx, fmt.Sprintf("%s/%s/%s/%s", s.RawBase, s.Repo, rev.SHA, b.Path), "")
	if err != nil {
		return nil, Version{}, err
	}

	var doc struct {
		Framework    string
		Provider     string
		Version      string
		Requirements []json.RawMessage
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, Version{}, fmt.Errorf("%s: %w", b.FileName(), err)
	}
	var v Version
	if b.Framework == "CIS" {
		v, err = ParseVersion(doc.Version)
	}
	switch {
	case doc.Framework != b.Framework:
		return nil, v, fmt.Errorf("%s: framework is %q, want %s", b.FileName(), doc.Framework, b.Framework)
	case !strings.EqualFold(doc.Provider, b.Provider.Label):
		return nil, v, fmt.Errorf("%s: provider is %q, want %s", b.FileName(), doc.Provider, b.Provider.Label)
	case err != nil || !v.Refines(b.Version):
		return nil, v, fmt.Errorf("%s: document version is %q", b.FileName(), doc.Version)
	case len(doc.Requirements) == 0:
		return nil, v, fmt.Errorf("%s: no requirements", b.FileName())
	}

	var out bytes.Buffer
	if err := json.Indent(&out, body, "", "    "); err != nil {
		return nil, v, err
	}
	out.WriteByte('\n')
	return out.Bytes(), v, nil
}

// Status is what Sync did with one document.
type Status int

const (
	UpToDate Status = iota // stored revision matches upstream
	Outdated               // upstream has a newer revision; run with Refresh
	Added                  // newly stored
	Updated                // replaced with the upstream revision
)

func (st Status) String() string {
	return [...]string{"up to date", "outdated", "added", "updated"}[st]
}

// Result reports what Sync did with one document.
type Result struct {
	Path   string // slash-separated path relative to the docs root
	Status Status
}

// Options control Sync.
type Options struct {
	All     bool             // collect every version, not only the latest
	Refresh bool             // replace documents whose upstream revision changed
	Match   string           // only handle documents whose path contains Match
	Now     func() time.Time // clock for the collection date; defaults to time.Now
}

// Sync stores the CIS benchmarks and standards of each provider under
// docsDir/<provider>/ and records their upstream revision in the manifest.
// Existing documents are only replaced when opts.Refresh is set.
func Sync(ctx context.Context, s *Source, docsDir string, providers []Provider, opts Options) (results []Result, err error) {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	m, err := manifest.Load(os.DirFS(docsDir))
	if err != nil {
		return nil, err
	}
	changed := false
	defer func() {
		if changed {
			if saveErr := m.Save(docsDir); err == nil {
				err = saveErr
			}
		}
	}()

	for _, p := range providers {
		var docs []Document
		if p.FilePrefix != "" {
			benchmarks, err := s.List(ctx, p)
			if err != nil {
				return results, err
			}
			if len(benchmarks) == 0 {
				return results, fmt.Errorf("no CIS benchmarks found for %s", p.Name)
			}
			if !opts.All {
				benchmarks = benchmarks[len(benchmarks)-1:]
			}
			docs = append(docs, benchmarks...)
		}
		docs = append(docs, s.Standards(p)...)

		for _, b := range docs {
			local, known := m.Find(b.Path)
			if !known {
				local = b.LocalPath()
			}
			if !strings.Contains(local, opts.Match) {
				continue
			}
			rev, err := s.Revision(ctx, b)
			if errors.Is(err, ErrNotPublished) && b.Framework != "CIS" {
				continue // not published for this provider at the source ref
			}
			if err != nil {
				return results, err
			}

			file := filepath.Join(docsDir, filepath.FromSlash(local))
			status := Added
			if _, err := os.Stat(file); err == nil {
				switch {
				case m[local].Revision == rev.SHA:
					status = UpToDate
				case opts.Refresh:
					status = Updated
				default:
					status = Outdated
				}
			} else if !errors.Is(err, os.ErrNotExist) {
				return results, err
			}

			if status == Added || status == Updated {
				data, v, err := s.Fetch(ctx, b, rev)
				if err != nil {
					return results, err
				}
				if status == Added && !known && b.Framework == "CIS" {
					// Name the file after the version stated in the document.
					b.Version = v
					local = b.LocalPath()
					file = filepath.Join(docsDir, filepath.FromSlash(local))
				}
				if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
					return results, err
				}
				if err := os.WriteFile(file, data, 0o644); err != nil {
					return results, err
				}
				m[local] = manifest.Entry{
					Source:    s.SourceURL(b, rev),
					Revision:  rev.SHA,
					Updated:   rev.Date.UTC().Format(time.DateOnly),
					Collected: opts.Now().Format(time.DateOnly),
				}
				changed = true
			}
			results = append(results, Result{Path: local, Status: status})
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

// Refines reports whether v is w or a patch release of w when w has no
// patch number, e.g. 4.0.1 refines 4.0.0.
func (v Version) Refines(w Version) bool {
	return v == w || (w[2] == 0 && v[0] == w[0] && v[1] == w[1])
}

// Less reports whether v is older than w.
func (v Version) Less(w Version) bool { return v.Compare(w) < 0 }
