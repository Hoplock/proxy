// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

// Command loadgen is the scale harness (docs/PLAN.md §10, phase 0020).
//
// It exists to replace arithmetic with measurement. D17 sizes the architecture
// off a chain of assumptions — an estate polled every minute, all of it over
// SSH, all of it through this proxy — and not one link in that chain has a
// number behind it. This binary produces the ones that are ours to produce:
// what a connection costs a proxy, what a live connection costs in memory, how
// many Hoplock Control requests a connection makes, whether the decision cache
// helps the UC2 fan-out pattern, and what an ephemeral-user account cycle costs
// a target.
//
// It is deliberately NOT part of the e2e compose topology (deploy/, phase
// 0012). That topology is the acceptance gate: it must stay fast and
// deterministic on a shared CI runner. A load run is neither, and putting the
// two in one place would either slow the gate down or make the load numbers
// noise. Separate processes, separate make targets, separate CI treatment.
//
// Usage:
//
//	loadgen -scenario load/scenarios/<name>.yaml [-proxy bin/hoplock-proxy] [-out load/results]
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const usage = `loadgen — the Hoplock Proxy scale harness (docs/PLAN.md §10, phase 0020)

Usage:
  loadgen -scenario <path> [flags]

Flags:
  -scenario string
        path to the scenario YAML (see load/scenarios/)
  -proxy string
        path to the hoplock-proxy binary (default "bin/hoplock-proxy")
  -out string
        directory to write the raw JSON result into; empty writes none
  -json
        print the raw JSON result to stdout instead of the report
`

func main() {
	fs := flag.NewFlagSet("loadgen", flag.ExitOnError)
	fs.Usage = func() { fmt.Fprint(fs.Output(), usage) }
	scenarioPath := fs.String("scenario", "", "path to the scenario YAML")
	proxyBin := fs.String("proxy", filepath.Join("bin", "hoplock-proxy"), "path to the hoplock-proxy binary")
	outDir := fs.String("out", "", "directory to write the raw JSON result into")
	asJSON := fs.Bool("json", false, "print the raw JSON result instead of the report")
	_ = fs.Parse(os.Args[1:])

	if err := run(*scenarioPath, *proxyBin, *outDir, *asJSON); err != nil {
		fmt.Fprintf(os.Stderr, "loadgen: %v\n", err)
		os.Exit(1)
	}
}

func run(scenarioPath, proxyBin, outDir string, asJSON bool) error {
	if scenarioPath == "" {
		return errors.New("-scenario is required")
	}
	sc, err := LoadScenario(scenarioPath)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var result any
	switch sc.Kind {
	case KindConnection:
		if _, err := os.Stat(proxyBin); err != nil {
			return fmt.Errorf("proxy binary %s not found (run `make build` first): %w", proxyBin, err)
		}
		workDir, err := os.MkdirTemp("", "loadgen-")
		if err != nil {
			return err
		}
		defer func() { _ = os.RemoveAll(workDir) }()

		fmt.Fprintf(os.Stderr, "loadgen: scenario %q, ~%s of load ahead\n",
			sc.Name, (sc.Run.Warmup + sc.Run.Duration).Round(time.Second))
		r, err := runConnection(ctx, sc, proxyBin, workDir)
		if err != nil {
			return err
		}
		result = r
		if !asJSON {
			writeConnectionReport(os.Stdout, r)
		}
	case KindProvisioning:
		fmt.Fprintf(os.Stderr, "loadgen: scenario %q, creating and removing real local accounts\n", sc.Name)
		r, err := runProvisioning(ctx, sc)
		if err != nil {
			return err
		}
		result = r
		if !asJSON {
			writeProvisioningReport(os.Stdout, r)
		}
	}

	blob, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	if asJSON {
		fmt.Println(string(blob))
	}
	if outDir != "" {
		if err := os.MkdirAll(outDir, 0o755); err != nil {
			return err
		}
		name := strings.ReplaceAll(sc.Name, "/", "-") + ".json"
		path := filepath.Join(outDir, name)
		if err := os.WriteFile(path, append(blob, '\n'), 0o644); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "loadgen: wrote %s\n", path)
	}
	return nil
}
