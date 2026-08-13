// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

// Command bastion is the SecureCommandProxy SSH bastion daemon.
//
// This is the scaffold binary: it parses flags and reports its version. The SSH
// listener, authentication, routing, and proxying are added in later phases
// (see docs/PLAN.md §10).
package main

import (
	"flag"
	"fmt"
	"os"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `bastion — SecureCommandProxy SSH bastion daemon

Usage:
  bastion [flags]

Flags:
  -config string
        path to the YAML bootstrap config (see config.example.yaml)
  -version
        print the version and exit
`

func main() {
	fs := flag.NewFlagSet("bastion", flag.ExitOnError)
	fs.Usage = func() { fmt.Fprint(fs.Output(), usage) }

	configPath := fs.String("config", "", "path to the YAML bootstrap config")
	showVersion := fs.Bool("version", false, "print the version and exit")

	// Parse cannot fail here: flag.ExitOnError exits on bad input.
	_ = fs.Parse(os.Args[1:])

	if *showVersion {
		fmt.Printf("bastion %s\n", version)
		return
	}

	fmt.Printf("bastion %s: scaffold build, no listener yet (config=%q)\n", version, *configPath)
}
