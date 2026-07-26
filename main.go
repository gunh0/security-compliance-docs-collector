// Command security-compliance-docs-collector serves security compliance
// documents (CIS benchmarks, etc.) through a web viewer.
package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gunh0/security-compliance-docs-collector/internal/web"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "listen address")
	docsDir := flag.String("docs", "docs", "directory containing compliance documents")
	flag.Parse()

	// os.Root confines every file access to docsDir, including via symlinks.
	root, err := os.OpenRoot(*docsDir)
	if err != nil {
		log.Fatal(err)
	}
	defer root.Close()

	srv := &http.Server{
		Addr:              *addr,
		Handler:           web.NewHandler(root.FS()),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Printf("serving %s on http://%s", *docsDir, *addr)
	log.Fatal(srv.ListenAndServe())
}
