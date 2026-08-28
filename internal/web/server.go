// Package web serves the compliance document list and JSON viewer.
package web

import (
	"embed"
	"errors"
	"html/template"
	"io/fs"
	"log"
	"net/http"

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
}

type indexView struct {
	Sections     []sectionView
	Documents    int
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
	Version      string
	Requirements int
	Updated      string
	Latest       bool
}

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

// newIndexView groups documents by top-level folder, newest version first.
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
	return v
}

func (v *indexView) addSection(name string, nodes []*catalog.Node) {
	s := sectionView{Name: name, Label: name}
	for i := len(nodes) - 1; i >= 0; i-- {
		n := nodes[i]
		d := docView{Path: n.Path, Title: n.Name, Latest: len(s.Docs) == 0}
		if m := n.Meta; m != nil {
			d.Title, d.Version, d.Requirements, d.Updated = m.Title, m.Version, m.Requirements, m.Updated
			if m.Provider != "" {
				s.Label = m.Provider
			}
			if label, ok := providerLabels[name]; ok {
				s.Label = label
			}
		}
		s.Docs = append(s.Docs, d)
		v.Documents++
		v.Requirements += d.Requirements
	}
	v.Sections = append(v.Sections, s)
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
