package web

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	docs := fstest.MapFS{
		"aws/cis_v3.0.0.json":         {Data: []byte(`{"Framework":"CIS","Provider":"AWS","Note":"</script><script>alert(1)</script>","Requirements":[{},{}]}`)},
		"aws/cis_v1.4.0.json":         {Data: []byte(`{"Framework":"CIS","Provider":"AWS","Requirements":[{}]}`)},
		"aws/notes.txt":               {Data: []byte("not a document")},
		"aws/iso27001_2022.json":      {Data: []byte(`{"Framework":"ISO27001","Name":"ISO/IEC 27001 Information Security Management Standard 2022","Version":"2022","Provider":"AWS","Requirements":[{}]}`)},
		"oraclecloud/cis_v3.1.0.json": {Data: []byte(`{"Framework":"CIS","Provider":"OracleCloud","Requirements":[{}]}`)},
		"manifest.json":               {Data: []byte(`{"aws/cis_v3.0.0.json":{"source":"https://github.com/prowler-cloud/prowler/blob/abc/prowler/compliance/aws/cis_3.0_aws.json","revision":"abc","updated":"2026-07-09","collected":"2026-07-10"}}`)},
	}
	srv := httptest.NewServer(NewHandler(docs))
	t.Cleanup(srv.Close)
	return srv
}

func get(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(b)
}

func TestIndex(t *testing.T) {
	srv := newTestServer(t)

	code, body := get(t, srv.URL+"/")
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if !strings.Contains(body, `href="/view/aws/cis_v3.0.0.json"`) {
		t.Errorf("index does not link the document:\n%s", body)
	}
	if !strings.Contains(body, "Oracle Cloud <span") {
		t.Errorf("provider display name not used:\n%s", body)
	}
	if strings.Contains(body, "notes.txt") {
		t.Error("index lists a non-JSON file")
	}
	// Newest version first, marked as latest; totals cover every document.
	latest := strings.Index(body, "v3.0.0")
	older := strings.Index(body, "v1.4.0")
	if latest < 0 || older < 0 || latest > older {
		t.Errorf("versions not listed newest first:\n%s", body)
	}
	// CIS benchmarks come before other frameworks of the same provider.
	iso := strings.Index(body, "ISO/IEC 27001 Information Security Management Standard 2022")
	if iso < 0 || iso < older {
		t.Errorf("standards not listed after CIS benchmarks:\n%s", body)
	}
	for _, want := range []string{`<span class="framework">ISO/IEC 27001</span>`, `<span class="pill">2022</span>`, "<dt>Frameworks</dt><dd>2</dd>", `data-framework="ISO/IEC 27001">ISO/IEC 27001</button>`, `<li data-framework="CIS">`} {
		if !strings.Contains(body, want) {
			t.Errorf("index does not contain %s", want)
		}
	}
	if !strings.Contains(body, `Updated <time datetime="2026-07-09">`) {
		t.Errorf("last updated date not shown:\n%s", body)
	}
	if strings.Contains(body, "manifest.json") {
		t.Error("index lists the manifest")
	}
	if strings.Count(body, "pill-latest") != 1 || !strings.Contains(body, "<dd>5</dd>") {
		t.Errorf("unexpected latest badge or requirement total:\n%s", body)
	}
}

func TestView(t *testing.T) {
	srv := newTestServer(t)

	code, body := get(t, srv.URL+"/view/aws/cis_v3.0.0.json")
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	for _, want := range []string{"Last updated", "2026-07-09", "Collected", "2026-07-10", "blob/abc/prowler/compliance/aws/cis_3.0_aws.json"} {
		if !strings.Contains(body, want) {
			t.Errorf("viewer does not show %q", want)
		}
	}
	if !strings.Contains(body, "<dd>2</dd>") {
		t.Errorf("requirement count not shown:\n%s", body)
	}
	if !strings.Contains(body, `"Framework":"CIS"`) {
		t.Errorf("document content not embedded:\n%s", body)
	}
	// Document content must not be able to break out of the <script> block.
	if strings.Contains(body, "</script><script>alert(1)") {
		t.Error("document content is not escaped inside <script>")
	}
}

func TestViewRejectsInvalidPaths(t *testing.T) {
	srv := newTestServer(t)

	for _, p := range []string{
		"/view/aws/notes.txt",
		"/view/aws/missing.json",
		"/view/..%2f..%2fgo.mod",
		"/view/..%2f..%2fetc%2fpasswd.json",
	} {
		if code, _ := get(t, srv.URL+p); code != http.StatusNotFound {
			t.Errorf("GET %s status = %d, want 404", p, code)
		}
	}
}

func TestStatic(t *testing.T) {
	srv := newTestServer(t)

	if code, _ := get(t, srv.URL+"/static/style.css"); code != http.StatusOK {
		t.Errorf("status = %d", code)
	}
}
