// Package catalog builds a browsable tree of compliance documents and
// reads individual documents from a docs file system.
package catalog

import (
	"encoding/json"
	"errors"
	"io/fs"
	"path"
	"sort"
	"strings"
)

// ErrNotFound is returned when a requested document does not exist or is
// not an allowed document path.
var ErrNotFound = errors.New("document not found")

// Node is a folder or a JSON document in the docs tree.
type Node struct {
	Name     string
	Path     string // slash-separated path relative to the docs root
	Children []*Node
}

// IsDir reports whether the node is a folder.
func (n *Node) IsDir() bool { return n.Children != nil }

// Build walks fsys and returns the top-level folders and documents.
// Only .json files are included; empty folders are dropped.
func Build(fsys fs.FS) ([]*Node, error) {
	return build(fsys, ".")
}

func build(fsys fs.FS, dir string) ([]*Node, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, err
	}

	nodes := []*Node{}
	for _, e := range entries {
		p := path.Join(dir, e.Name())
		switch {
		case e.IsDir():
			children, err := build(fsys, p)
			if err != nil {
				return nil, err
			}
			if len(children) > 0 {
				nodes = append(nodes, &Node{Name: e.Name(), Path: p, Children: children})
			}
		case isDocument(p):
			nodes = append(nodes, &Node{Name: e.Name(), Path: p})
		}
	}

	sort.SliceStable(nodes, func(i, j int) bool {
		if nodes[i].IsDir() != nodes[j].IsDir() {
			return nodes[i].IsDir()
		}
		return nodes[i].Name < nodes[j].Name
	})
	return nodes, nil
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
	return strings.HasSuffix(p, ".json")
}
