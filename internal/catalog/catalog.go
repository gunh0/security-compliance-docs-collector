// Package catalog builds a browsable tree of compliance documents and
// reads individual documents from a docs file system.
package catalog

import (
	"encoding/json"
	"errors"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/gunh0/security-compliance-docs-collector/internal/manifest"
)

// ErrNotFound is returned when a requested document does not exist or is
// not an allowed document path.
var ErrNotFound = errors.New("document not found")

// Node is a folder or a JSON document in the docs tree.
type Node struct {
	Name     string
	Path     string // slash-separated path relative to the docs root
	Children []*Node
	Meta     *Meta // document summary; nil for folders and unreadable documents
}

// Meta summarizes a compliance document.
type Meta struct {
	Title        string // e.g. "CIS Amazon Web Services Foundations Benchmark"
	Version      string // e.g. "7.0.0", taken from the file name when possible
	Framework    string
	Provider     string
	Description  string
	Requirements int

	// From the manifest; empty for documents that were not collected.
	Updated   string // date the upstream document last changed
	Collected string // date the document was stored
	Source    string // upstream URL
}

// IsDir reports whether the node is a folder.
func (n *Node) IsDir() bool { return n.Children != nil }

// Build walks fsys and returns the top-level folders and documents.
// Only .json files are included; empty folders are dropped.
func Build(fsys fs.FS) ([]*Node, error) {
	m, err := manifest.Load(fsys)
	if err != nil {
		return nil, err
	}
	return build(fsys, ".", m)
}

func build(fsys fs.FS, dir string, m manifest.Manifest) ([]*Node, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, err
	}

	nodes := []*Node{}
	for _, e := range entries {
		p := path.Join(dir, e.Name())
		switch {
		case e.IsDir():
			children, err := build(fsys, p, m)
			if err != nil {
				return nil, err
			}
			if len(children) > 0 {
				nodes = append(nodes, &Node{Name: e.Name(), Path: p, Children: children})
			}
		case isDocument(p):
			nodes = append(nodes, &Node{Name: e.Name(), Path: p, Meta: readMeta(fsys, p, m)})
		}
	}

	sort.SliceStable(nodes, func(i, j int) bool {
		if nodes[i].IsDir() != nodes[j].IsDir() {
			return nodes[i].IsDir()
		}
		return naturalLess(nodes[i].Name, nodes[j].Name)
	})
	return nodes, nil
}

// fileNamePattern matches names such as "cis_kubernetes_benchmark_v1.8.0.json".
var fileNamePattern = regexp.MustCompile(`^(.+)_v(\d+(?:\.\d+)*)\.json$`)

// Describe summarizes the document stored at p in fsys, as returned by Read.
func Describe(fsys fs.FS, p string, doc json.RawMessage) (*Meta, error) {
	m, err := manifest.Load(fsys)
	if err != nil {
		return nil, err
	}
	meta, err := describe(path.Base(p), doc)
	if err != nil {
		return nil, err
	}
	meta.addSource(m[p])
	return meta, nil
}

func readMeta(fsys fs.FS, p string, m manifest.Manifest) *Meta {
	b, err := fs.ReadFile(fsys, p)
	if err != nil {
		return nil
	}
	meta, err := describe(path.Base(p), b)
	if err != nil {
		return nil
	}
	meta.addSource(m[p])
	return meta
}

func (meta *Meta) addSource(e manifest.Entry) {
	meta.Updated, meta.Collected, meta.Source = e.Updated, e.Collected, e.Source
}

func describe(name string, b []byte) (*Meta, error) {
	var doc struct {
		Framework    string
		Provider     string
		Version      string
		Description  string
		Requirements []struct{}
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}

	m := &Meta{
		Title:        strings.TrimSuffix(name, ".json"),
		Version:      doc.Version,
		Framework:    doc.Framework,
		Provider:     doc.Provider,
		Description:  doc.Description,
		Requirements: len(doc.Requirements),
	}
	if sub := fileNamePattern.FindStringSubmatch(name); sub != nil {
		m.Title = titleFromSlug(sub[1])
		m.Version = sub[2]
	}
	return m, nil
}

// titleFromSlug turns "cis_amazon_web_services_foundations_benchmark" into
// "CIS Amazon Web Services Foundations Benchmark".
func titleFromSlug(slug string) string {
	words := strings.Split(slug, "_")
	for i, w := range words {
		switch w {
		case "":
		case "cis", "aws", "gcp":
			words[i] = strings.ToUpper(w)
		default:
			r := []rune(w)
			r[0] = unicode.ToUpper(r[0])
			words[i] = string(r)
		}
	}
	return strings.Join(words, " ")
}

// naturalLess compares strings treating digit runs as numbers, so that
// "v1.8.0" sorts before "v1.10.0".
func naturalLess(a, b string) bool {
	for a != "" && b != "" {
		da, db := leadingDigits(a), leadingDigits(b)
		if da != "" && db != "" {
			na, _ := strconv.Atoi(da)
			nb, _ := strconv.Atoi(db)
			if na != nb {
				return na < nb
			}
			a, b = a[len(da):], b[len(db):]
			continue
		}
		if a[0] != b[0] {
			return a[0] < b[0]
		}
		a, b = a[1:], b[1:]
	}
	return len(a) < len(b)
}

func leadingDigits(s string) string {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	return s[:i]
}

// Read returns the raw JSON of the document at p. Paths that escape the
// docs root, are not .json files, or do not hold valid JSON are rejected.
func Read(fsys fs.FS, p string) (json.RawMessage, error) {
	if !fs.ValidPath(p) || !isDocument(p) {
		return nil, ErrNotFound
	}

	b, err := fs.ReadFile(fsys, p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if !json.Valid(b) {
		return nil, errors.New("invalid JSON document: " + p)
	}
	return json.RawMessage(b), nil
}

func isDocument(p string) bool {
	return strings.HasSuffix(p, ".json") && p != manifest.File
}
