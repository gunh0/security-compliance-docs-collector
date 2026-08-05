package catalog

import (
	"errors"
	"testing"
	"testing/fstest"
)

func testFS() fstest.MapFS {
	return fstest.MapFS{
		"aws/cis_v3.0.0.json":   {Data: []byte(`{"Version":"3.0"}`)},
		"aws/cis_v1.4.0.json":   {Data: []byte(`{"Version":"1.4"}`)},
		"aws/notes.txt":         {Data: []byte("ignored")},
		"azure/cis_v2.1.0.json": {Data: []byte(`{"Version":"2.1"}`)},
		"empty/readme.md":       {Data: []byte("ignored")},
		"broken.json":           {Data: []byte(`{"Version":`)},
	}
}

func TestBuild(t *testing.T) {
	nodes, err := Build(testFS())
	if err != nil {
		t.Fatal(err)
	}

	// Folders first, then documents; folders without documents are dropped.
	want := []string{"aws", "azure", "broken.json"}
	if len(nodes) != len(want) {
		t.Fatalf("got %d top-level nodes, want %d", len(nodes), len(want))
	}
	for i, name := range want {
		if nodes[i].Name != name {
			t.Errorf("nodes[%d] = %q, want %q", i, nodes[i].Name, name)
		}
	}

	aws := nodes[0].Children
	if len(aws) != 2 || aws[0].Path != "aws/cis_v1.4.0.json" || aws[1].Path != "aws/cis_v3.0.0.json" {
		t.Errorf("unexpected aws children: %+v", aws)
	}
}

func TestRead(t *testing.T) {
	fsys := testFS()

	got, err := Read(fsys, "aws/cis_v3.0.0.json")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"Version":"3.0"}` {
		t.Errorf("got %s", got)
	}

	for _, p := range []string{
		"../main.go",
		"../../etc/passwd.json",
		"/aws/cis_v3.0.0.json",
		"aws/notes.txt",
		"aws/missing.json",
	} {
		if _, err := Read(fsys, p); !errors.Is(err, ErrNotFound) {
			t.Errorf("Read(%q) error = %v, want ErrNotFound", p, err)
		}
	}

	if _, err := Read(fsys, "broken.json"); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("Read(broken.json) error = %v, want invalid JSON error", err)
	}
}

func TestBuildMeta(t *testing.T) {
	fsys := fstest.MapFS{
		"k8s/cis_kubernetes_benchmark_v1.10.0.json": {Data: []byte(`{"Framework":"CIS","Provider":"Kubernetes","Version":"1.10","Requirements":[{},{}]}`)},
		"k8s/cis_kubernetes_benchmark_v1.8.0.json":  {Data: []byte(`{"Framework":"CIS","Provider":"Kubernetes","Version":"1.8","Requirements":[{}]}`)},
		"k8s/broken.json": {Data: []byte(`{`)},
	}
	nodes, err := Build(fsys)
	if err != nil {
		t.Fatal(err)
	}

	docs := nodes[0].Children
	// Version numbers sort numerically: v1.8.0 before v1.10.0.
	if docs[1].Name != "cis_kubernetes_benchmark_v1.8.0.json" || docs[2].Name != "cis_kubernetes_benchmark_v1.10.0.json" {
		t.Fatalf("unexpected order: %s, %s, %s", docs[0].Name, docs[1].Name, docs[2].Name)
	}
	if docs[0].Meta != nil {
		t.Error("invalid document has metadata")
	}

	m := docs[2].Meta
	want := Meta{Title: "CIS Kubernetes Benchmark", Version: "1.10.0", Framework: "CIS", Provider: "Kubernetes", Requirements: 2}
	if m == nil || *m != want {
		t.Errorf("Meta = %+v, want %+v", m, want)
	}
}

func TestNaturalLess(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"v1.8.0", "v1.10.0", true},
		{"v1.10.0", "v1.8.0", false},
		{"v2.0.0", "v2.0.1", true},
		{"a", "b", true},
		{"a", "a1", true},
	} {
		if got := naturalLess(c.a, c.b); got != c.want {
			t.Errorf("naturalLess(%q, %q) = %v", c.a, c.b, got)
		}
	}
}
