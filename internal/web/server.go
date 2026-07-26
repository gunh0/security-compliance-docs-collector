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

func index(docs fs.FS) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tree, err := catalog.Build(docs)
		if err != nil {
			serverError(w, err)
			return
		}
		render(w, indexTmpl, tree)
	}
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
		render(w, viewTmpl, struct {
			FilePath string
			Content  any
		}{p, content})
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
