// Package manifest records where each collected document came from.
package manifest

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// File is the manifest's file name in the docs root.
const File = "manifest.json"

// Entry describes the upstream revision of one document.
type Entry struct {
	Source    string `json:"source"`    // upstream URL pinned to Revision
	Revision  string `json:"revision"`  // upstream commit that last changed the document
	Updated   string `json:"updated"`   // date of Revision, YYYY-MM-DD
	Collected string `json:"collected"` // date the document was stored, YYYY-MM-DD
}

// Manifest maps slash-separated document paths, relative to the docs
// root, to their entries.
type Manifest map[string]Entry

// Find returns the path of the document collected from upstreamPath.
func (m Manifest) Find(upstreamPath string) (string, bool) {
	for p, e := range m {
		if strings.HasSuffix(e.Source, "/"+upstreamPath) {
			return p, true
		}
	}
	return "", false
}

// Load reads the manifest from the docs root. A missing manifest is empty.
func Load(docs fs.FS) (Manifest, error) {
	b, err := fs.ReadFile(docs, File)
	if errors.Is(err, fs.ErrNotExist) {
		return Manifest{}, nil
	}
	if err != nil {
		return nil, err
	}
	m := Manifest{}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// Save writes the manifest to dir with sorted keys.
func (m Manifest) Save(dir string) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, File), append(b, '\n'), 0o644)
}
