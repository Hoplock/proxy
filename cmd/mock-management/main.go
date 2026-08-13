// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

// Command mock-management is the reference/mock management server used for
// development and CI (docs/PLAN.md, D3).
//
// This is the scaffold binary: it parses flags and reports its version. The API
// implementation lands with the contract in phase 0002.
package main

import (
	"flag"
	"fmt"
	"os"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `mock-management — SecureCommandProxy mock management server

Usage:
  mock-management [flags]

Flags:
  -listen string
        host:port to serve the mock management API on (default "127.0.0.1:8080")
  -version
        print the version and exit
`

func main() {
	fs := flag.NewFlagSet("mock-management", flag.ExitOnError)
	fs.Usage = func() { fmt.Fprint(fs.Output(), usage) }

	listenAddr := fs.String("listen", "127.0.0.1:8080", "host:port to serve the mock management API on")
	showVersion := fs.Bool("version", false, "print the version and exit")

	// Parse cannot fail here: flag.ExitOnError exits on bad input.
	_ = fs.Parse(os.Args[1:])

	if *showVersion {
		fmt.Printf("mock-management %s\n", version)
		return
	}

	fmt.Printf("mock-management %s: scaffold build, no API yet (listen=%q)\n", version, *listenAddr)
}
