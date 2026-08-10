package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gunh0/security-compliance-docs-collector/internal/manifest"
)

var aws = Providers[0]

// upstream fakes the GitHub API and raw content hosts for the aws directory.
// revisions maps an upstream file name to its latest commit; docs maps
// "<sha>/<name>" to the file content at that commit.
type upstream struct {
	revisions map[string]string
	docs      map[string]string
}

func (u *upstream) source(t *testing.T) *Source {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	const dir = "prowler/compliance/aws"
	mux.HandleFunc("GET /repos/prowler-cloud/prowler/contents/"+dir, func(w http.ResponseWriter, r *http.Request) {
		type entry struct {
			Name string `json:"name"`
			Type string `json:"type"`
		}
		entries := []entry{{"__init__.py", "file"}, {"legacy", "dir"}}
		for name := range u.revisions {
			entries = append(entries, entry{name, "file"})
		}
		json.NewEncoder(w).Encode(entries)
	})
	mux.HandleFunc("GET /repos/prowler-cloud/prowler/commits", func(w http.ResponseWriter, r *http.Request) {
		sha, ok := u.revisions[strings.TrimPrefix(r.URL.Query().Get("path"), dir+"/")]
		if !ok || r.URL.Query().Get("sha") != "master" {
			json.NewEncoder(w).Encode([]any{})
			return
		}
		fmt.Fprintf(w, `[{"sha":%q,"commit":{"committer":{"date":"2026-07-09T08:30:00Z"}}}]`, sha)
	})
	mux.HandleFunc("GET /raw/prowler-cloud/prowler/{sha}/"+dir+"/{name}", func(w http.ResponseWriter, r *http.Request) {
		doc, ok := u.docs[r.PathValue("sha")+"/"+r.PathValue("name")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, doc)
	})

	s := Prowler()
	s.APIBase = srv.URL
	s.RawBase = srv.URL + "/raw"
	s.Client = srv.Client()
	return s
}

func doc(provider, version string) string {
	return fmt.Sprintf(`{"Framework":"CIS","Version":%q,"Provider":%q,"Requirements":[{"Id":"1.1"}]}`, version, provider)
}

func fixedClock() time.Time { return time.Date(2026, 7, 10, 21, 0, 0, 0, time.UTC) }

func TestList(t *testing.T) {
	u := &upstream{revisions: map[string]string{
		"cis_1.10_aws.json":  "a",
		"cis_1.4_aws.json":   "a",
		"cis_2.0.1_aws.json": "a",
		"cisa_aws.json":      "a",
		"iso27001_aws.json":  "a",
	}}

	benchmarks, err := u.source(t).List(context.Background(), aws)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, b := range benchmarks {
		got = append(got, b.LocalPath())
	}
	want := []string{
		"aws/cis_amazon_web_services_foundations_benchmark_v1.4.0.json",
		"aws/cis_amazon_web_services_foundations_benchmark_v1.10.0.json",
		"aws/cis_amazon_web_services_foundations_benchmark_v2.0.1.json",
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("got %v, want %v", got, want)
	}
	if benchmarks[0].Path != "prowler/compliance/aws/cis_1.4_aws.json" {
		t.Errorf("upstream path = %q", benchmarks[0].Path)
	}
}

func TestFetchValidates(t *testing.T) {
	u := &upstream{
		revisions: map[string]string{},
		docs: map[string]string{
			"r/cis_1.0_aws.json": doc("AWS", "1.0"),
			"r/cis_2.0_aws.json": doc("Azure", "2.0"),
			"r/cis_3.0_aws.json": doc("AWS", "2.0"),
			"r/cis_4.0_aws.json": `{"Framework":"CIS","Version":"4.0","Provider":"AWS","Requirements":[]}`,
			"r/cis_5.0_aws.json": `not json`,
		},
	}
	for name := range u.docs {
		u.revisions[strings.TrimPrefix(name, "r/")] = "r"
	}
	s := u.source(t)
	benchmarks, err := s.List(context.Background(), aws)
	if err != nil {
		t.Fatal(err)
	}
	rev := Revision{SHA: "r"}

	got, err := s.Fetch(context.Background(), benchmarks[0], rev)
	if err != nil {
		t.Fatalf("valid document: %v", err)
	}
	if !strings.Contains(string(got), "\n    \"Framework\": \"CIS\"") {
		t.Errorf("document not indented with four spaces:\n%s", got)
	}

	for _, b := range benchmarks[1:] {
		if _, err := s.Fetch(context.Background(), b, rev); err == nil {
			t.Errorf("Fetch(%s) succeeded, want error", b.FileName())
		}
	}
}

func TestSync(t *testing.T) {
	u := &upstream{
		revisions: map[string]string{"cis_1.4_aws.json": "r1", "cis_7.0_aws.json": "r1"},
		docs: map[string]string{
			"r1/cis_1.4_aws.json": doc("AWS", "1.4"),
			"r1/cis_7.0_aws.json": doc("AWS", "7.0"),
			"r2/cis_7.0_aws.json": `{"Framework":"CIS","Version":"7.0","Provider":"AWS","Requirements":[{"Id":"1.1"},{"Id":"1.2"}]}`,
		},
	}
	s := u.source(t)
	dir := t.TempDir()
	sync := func(opts Options) []Result {
		t.Helper()
		opts.Now = fixedClock
		results, err := Sync(context.Background(), s, dir, []Provider{aws}, opts)
		if err != nil {
			t.Fatal(err)
		}
		return results
	}
	statuses := func(results []Result) string {
		var out []string
		for _, r := range results {
			out = append(out, filepath.Base(r.Path)+"="+r.Status.String())
		}
		return strings.Join(out, ",")
	}
	const (
		v14 = "cis_amazon_web_services_foundations_benchmark_v1.4.0.json"
		v70 = "cis_amazon_web_services_foundations_benchmark_v7.0.0.json"
	)

	if got := statuses(sync(Options{})); got != v70+"=added" {
		t.Fatalf("latest only: %s", got)
	}
	if got := statuses(sync(Options{All: true, Match: "v1.4"})); got != v14+"=added" {
		t.Fatalf("match: %s", got)
	}

	m, err := manifest.Load(os.DirFS(dir))
	if err != nil {
		t.Fatal(err)
	}
	want := manifest.Entry{
		Source:    "https://github.com/prowler-cloud/prowler/blob/r1/prowler/compliance/aws/cis_7.0_aws.json",
		Revision:  "r1",
		Updated:   "2026-07-09",
		Collected: "2026-07-10",
	}
	if got := m["aws/"+v70]; got != want {
		t.Errorf("manifest entry = %+v, want %+v", got, want)
	}

	// Upstream changes 7.0: reported, and only replaced with Refresh.
	u.revisions["cis_7.0_aws.json"] = "r2"
	if got := statuses(sync(Options{All: true})); got != v14+"=up to date,"+v70+"=outdated" {
		t.Fatalf("outdated: %s", got)
	}
	if got := statuses(sync(Options{Refresh: true})); got != v70+"=updated" {
		t.Fatalf("refresh: %s", got)
	}
	b, err := os.ReadFile(filepath.Join(dir, "aws", v70))
	if err != nil || !strings.Contains(string(b), `"Id": "1.2"`) {
		t.Errorf("document not refreshed: %s, %v", b, err)
	}
	if m, _ := manifest.Load(os.DirFS(dir)); m["aws/"+v70].Revision != "r2" {
		t.Errorf("manifest not refreshed: %+v", m["aws/"+v70])
	}
}

func TestParseVersion(t *testing.T) {
	for in, want := range map[string]string{"3.0": "3.0.0", "1.10": "1.10.0", "2.0.1": "2.0.1", "7": "7.0.0"} {
		v, err := ParseVersion(in)
		if err != nil || v.String() != want {
			t.Errorf("ParseVersion(%q) = %v, %v; want %s", in, v, err, want)
		}
	}
	for _, in := range []string{"", "v1.0", "1.0.0.0", "1.x"} {
		if _, err := ParseVersion(in); err == nil {
			t.Errorf("ParseVersion(%q) succeeded, want error", in)
		}
	}
}
