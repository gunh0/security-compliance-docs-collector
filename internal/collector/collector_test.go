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
)

var aws = Providers[0]

// newTestSource serves a GitHub contents listing for aws and the raw
// documents it points to.
func newTestSource(t *testing.T, docs map[string]string) *Source {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("GET /repos/prowler-cloud/prowler/contents/prowler/compliance/aws", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("ref") != "master" {
			http.Error(w, "unexpected ref", http.StatusBadRequest)
			return
		}
		type entry struct {
			Name        string `json:"name"`
			Type        string `json:"type"`
			DownloadURL string `json:"download_url"`
		}
		entries := []entry{{Name: "__init__.py", Type: "file"}, {Name: "legacy", Type: "dir"}}
		for name := range docs {
			entries = append(entries, entry{Name: name, Type: "file", DownloadURL: srv.URL + "/raw/" + name})
		}
		json.NewEncoder(w).Encode(entries)
	})
	mux.HandleFunc("GET /raw/{name}", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, docs[r.PathValue("name")])
	})

	s := Prowler()
	s.APIBase = srv.URL
	s.Client = srv.Client()
	return s
}

func doc(provider, version string) string {
	return fmt.Sprintf(`{"Framework":"CIS","Version":%q,"Provider":%q,"Requirements":[{"Id":"1.1"}]}`, version, provider)
}

func TestList(t *testing.T) {
	s := newTestSource(t, map[string]string{
		"cis_1.10_aws.json":  doc("AWS", "1.10"),
		"cis_1.4_aws.json":   doc("AWS", "1.4"),
		"cis_2.0.1_aws.json": doc("AWS", "2.0.1"),
		"cisa_aws.json":      doc("AWS", "1.0"),
		"iso27001_aws.json":  doc("AWS", "2013"),
	})

	benchmarks, err := s.List(context.Background(), aws)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, b := range benchmarks {
		got = append(got, b.FileName())
	}
	want := []string{
		"cis_amazon_web_services_foundations_benchmark_v1.4.0.json",
		"cis_amazon_web_services_foundations_benchmark_v1.10.0.json",
		"cis_amazon_web_services_foundations_benchmark_v2.0.1.json",
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestFetchValidates(t *testing.T) {
	s := newTestSource(t, map[string]string{
		"cis_1.0_aws.json": doc("AWS", "1.0"),
		"cis_2.0_aws.json": doc("Azure", "2.0"),
		"cis_3.0_aws.json": doc("AWS", "2.0"),
		"cis_4.0_aws.json": `{"Framework":"CIS","Version":"4.0","Provider":"AWS","Requirements":[]}`,
		"cis_5.0_aws.json": `not json`,
	})
	benchmarks, err := s.List(context.Background(), aws)
	if err != nil {
		t.Fatal(err)
	}

	got, err := s.Fetch(context.Background(), benchmarks[0])
	if err != nil {
		t.Fatalf("valid document: %v", err)
	}
	if !strings.Contains(string(got), "\n    \"Framework\": \"CIS\"") {
		t.Errorf("document not indented with four spaces:\n%s", got)
	}

	for _, b := range benchmarks[1:] {
		if _, err := s.Fetch(context.Background(), b); err == nil {
			t.Errorf("Fetch(%s) succeeded, want error", b.FileName())
		}
	}
}

func TestSync(t *testing.T) {
	s := newTestSource(t, map[string]string{
		"cis_1.4_aws.json": doc("AWS", "1.4"),
		"cis_3.0_aws.json": doc("AWS", "3.0"),
		"cis_7.0_aws.json": doc("AWS", "7.0"),
	})
	dir := t.TempDir()
	existing := filepath.Join(dir, "aws", "cis_amazon_web_services_foundations_benchmark_v3.0.0.json")
	if err := os.MkdirAll(filepath.Dir(existing), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(existing, []byte("local"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Latest only.
	results, err := Sync(context.Background(), s, dir, []Provider{aws}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || !results[0].Added || !strings.HasSuffix(results[0].Path, "_v7.0.0.json") {
		t.Fatalf("unexpected results: %+v", results)
	}

	// All versions: 1.4 is added, 3.0 and 7.0 already exist.
	results, err = Sync(context.Background(), s, dir, []Provider{aws}, true)
	if err != nil {
		t.Fatal(err)
	}
	var added []string
	for _, r := range results {
		if r.Added {
			added = append(added, filepath.Base(r.Path))
		}
	}
	if len(results) != 3 || len(added) != 1 || added[0] != "cis_amazon_web_services_foundations_benchmark_v1.4.0.json" {
		t.Fatalf("unexpected results: %+v", results)
	}

	if b, _ := os.ReadFile(existing); string(b) != "local" {
		t.Error("existing document was overwritten")
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
