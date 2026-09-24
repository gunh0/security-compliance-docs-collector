// Package web serves the compliance document list and JSON viewer.
package web

import (
	"embed"
	"errors"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"sort"
	"strings"

	"github.com/gunh0/security-compliance-docs-collector/internal/catalog"
)

//go:embed templates static
var assets embed.FS

var (
	indexTmpl = template.Must(template.ParseFS(assets, "templates/index.html"))
	viewTmpl  = template.Must(template.ParseFS(assets, "templates/view_file.html"))
)

// NewHandler returns an http.Handler that serves the documents in docs.
func NewHandler(docs fs.FS) http.Handler {
	static, err := fs.Sub(assets, "static")
	if err != nil {
		panic(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", index(docs))
	mux.HandleFunc("GET /view/{path...}", view(docs))
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	return mux
}

// providerLabels are display names for provider folders whose document
// Provider field is not meant for display.
var providerLabels = map[string]string{
	"gcp":          "Google Cloud",
	"oraclecloud":  "Oracle Cloud",
	"alibabacloud": "Alibaba Cloud",
	"nhn":          "NHN Cloud",
}

// frameworkLabels are display names for document Framework fields.
var frameworkLabels = map[string]string{
	"ISO27001":               "ISO/IEC 27001",
	"KISA-ISMS-P":            "KISA ISMS-P",
	"NIST-800-53-Revision-5": "NIST SP 800-53",
	"NIST-CSF":               "NIST CSF",
	"AWS-Foundational-Security-Best-Practices":       "AWS FSBP",
	"AWS-Well-Architected-Framework-Security-Pillar": "AWS Well-Architected",
	"SOC2":         "SOC 2",
	"MITRE-ATTACK": "MITRE ATT&CK",
}

func frameworkLabel(f string) string {
	if label, ok := frameworkLabels[f]; ok {
		return label
	}
	return strings.ReplaceAll(f, "-", " ")
}

type indexView struct {
	Sections     []sectionView
	Documents    int
	Frameworks   []string // display names, CIS first
	Requirements int
}

type sectionView struct {
	Name  string // folder name, e.g. "aws"
	Label string // provider name shown to users, e.g. "AWS"
	Docs  []docView
}

type docView struct {
	Path         string
	Title        string
	Framework    string
	Version      string
	Requirements int
	Updated      string
	Latest       bool
}

// VersionLabel formats the version for display.
func (d docView) VersionLabel() string { return catalog.VersionLabel(d.Version) }

func index(docs fs.FS) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tree, err := catalog.Build(docs)
		if err != nil {
			serverError(w, err)
			return
		}
		render(w, indexTmpl, newIndexView(tree))
	}
}

// newIndexView groups documents by top-level folder and, within a folder,
// by framework: CIS first, then by name, newest version first.
func newIndexView(tree []*catalog.Node) indexView {
	var v indexView
	var loose []*catalog.Node
	for _, n := range tree {
		if !n.IsDir() {
			loose = append(loose, n)
			continue
		}
		v.addSection(n.Name, documents(n.Children))
	}
	if len(loose) > 0 {
		v.addSection("other", loose)
	}

	seen := map[string]bool{}
	for _, s := range v.Sections {
		for _, d := range s.Docs {
			if d.Framework != "" && !seen[d.Framework] {
				seen[d.Framework] = true
				v.Frameworks = append(v.Frameworks, d.Framework)
			}
		}
	}
	sort.Slice(v.Frameworks, func(i, j int) bool { return frameworkLess(v.Frameworks[i], v.Frameworks[j]) })
	return v
}

func (v *indexView) addSection(name string, nodes []*catalog.Node) {
	s := sectionView{Name: name, Label: name}
	if label, ok := providerLabels[name]; ok {
		s.Label = label
	}

	// nodes are in natural order, so walking backwards yields newest first.
	perFramework := map[string]int{}
	for i := len(nodes) - 1; i >= 0; i-- {
		n := nodes[i]
		d := docView{Path: n.Path, Title: n.Name}
		if m := n.Meta; m != nil {
			d.Title, d.Version, d.Requirements, d.Updated = m.Title, m.Version, m.Requirements, m.Updated
			if m.Framework != "" {
				d.Framework = frameworkLabel(m.Framework)
			}
			if _, ok := providerLabels[name]; !ok && m.Provider != "" {
				s.Label = m.Provider
			}
		}
		perFramework[d.Framework]++
		s.Docs = append(s.Docs, d)
		v.Documents++
		v.Requirements += d.Requirements
	}

	sort.SliceStable(s.Docs, func(i, j int) bool { return frameworkLess(s.Docs[i].Framework, s.Docs[j].Framework) })
	for i := range s.Docs {
		f := s.Docs[i].Framework
		s.Docs[i].Latest = perFramework[f] > 1 && (i == 0 || s.Docs[i-1].Framework != f)
	}
	v.Sections = append(v.Sections, s)
}

// frameworkLess orders CIS before other frameworks, then by name.
func frameworkLess(a, b string) bool {
	if (a == "CIS") != (b == "CIS") {
		return a == "CIS"
	}
	return a < b
}

// documents flattens the documents under nodes, keeping their order.
func documents(nodes []*catalog.Node) []*catalog.Node {
	var out []*catalog.Node
	for _, n := range nodes {
		if n.IsDir() {
			out = append(out, documents(n.Children)...)
		} else {
			out = append(out, n)
		}
	}
	return out
}

func view(docs fs.FS) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p := r.PathValue("path")
		content, err := catalog.Read(docs, p)
		if errors.Is(err, catalog.ErrNotFound) {
			http.Error(w, "File not found", http.StatusNotFound)
			return
		}
		if err != nil {
			serverError(w, err)
			return
		}
		meta, err := catalog.Describe(docs, p, content)
		if err != nil {
			serverError(w, err)
			return
		}
		render(w, viewTmpl, struct {
			FilePath string
			Meta     *catalog.Meta
			Content  any
		}{p, meta, content})
	}
}

func render(w http.ResponseWriter, t *template.Template, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.Execute(w, data); err != nil {
		log.Printf("render %s: %v", t.Name(), err)
	}
}

func serverError(w http.ResponseWriter, err error) {
	log.Print(err)
	http.Error(w, "Internal Server Error", http.StatusInternalServerError)
}
