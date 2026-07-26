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
