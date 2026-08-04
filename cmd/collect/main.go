// Command collect downloads the latest CIS benchmark documents from the
// Prowler compliance catalog into the docs directory.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/gunh0/security-compliance-docs-collector/internal/collector"
)

func main() {
	docsDir := flag.String("docs", "docs", "directory to store documents in")
	all := flag.Bool("all", false, "collect every published version, not only the latest")
	ref := flag.String("ref", "master", "Prowler branch, tag or commit to collect from")
	flag.Parse()

	src := collector.Prowler()
	src.Ref = *ref
	src.Token = os.Getenv("GITHUB_TOKEN")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	results, err := collector.Sync(ctx, src, *docsDir, collector.Providers, *all)
	added := 0
	for _, r := range results {
		status := "up to date"
		if r.Added {
			status = "added"
			added++
		}
		fmt.Printf("%-10s %s\n", status, r.Path)
	}
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%d new document(s) from %s@%s\n", added, src.Repo, src.Ref)
}
