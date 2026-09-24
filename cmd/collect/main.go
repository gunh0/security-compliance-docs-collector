// Command collect downloads CIS benchmarks and other compliance documents from the
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
	refresh := flag.Bool("refresh", false, "replace documents that changed upstream")
	match := flag.String("match", "", "only collect documents whose path contains this string, e.g. aws/")
	ref := flag.String("ref", "master", "Prowler branch, tag or commit to collect from")
	flag.Parse()

	src := collector.Prowler()
	src.Ref = *ref
	src.Token = os.Getenv("GITHUB_TOKEN")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	results, err := collector.Sync(ctx, src, *docsDir, collector.Providers, collector.Options{
		All:     *all,
		Refresh: *refresh,
		Match:   *match,
	})
	counts := map[collector.Status]int{}
	for _, r := range results {
		counts[r.Status]++
		fmt.Printf("%-10s %s\n", r.Status, r.Path)
	}
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%d added, %d updated, %d outdated, %d up to date (%s@%s)\n",
		counts[collector.Added], counts[collector.Updated], counts[collector.Outdated], counts[collector.UpToDate], src.Repo, src.Ref)
	if counts[collector.Outdated] > 0 {
		fmt.Println("run with -refresh to update outdated documents")
	}
}
