// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package filter

import (
	"fmt"
	"strings"

	"github.com/hoplock/proxy/internal/control"
)

// decideRestricted is the boundary (D12): the command is parsed into an
// argument vector, that vector must be covered COMPLETELY by one entry of the
// permitted list, and everything else is denied.
//
// Three properties are what earn the word "enforcement" here, and each of them
// is a line of code below rather than a claim:
//
//   - a command that does not parse unambiguously is denied, not approximated;
//   - argv[0] is compared to the named executable exactly — no PATH search, no
//     basename comparison, no symlink resolution, because every one of those
//     would accept a name the server did not write;
//   - an argument no spec covers is denied, so the shape of a permitted command
//     is bounded by what the server wrote and there is no trailing allowance.
//
// The denial is presented to the user exactly as a blocked command is: the tier
// that decided is in the audit record, not on the terminal.
func (e *Engine) decideRestricted(command string) Decision {
	d := Decision{Tier: TierRestricted, RuleIndex: -1, Command: command}

	argv, err := ParseArgv(command)
	if err != nil {
		d.Action = control.FilterActionBlockCommand
		d.Detail = "the command is not one unambiguous argument vector: " + err.Error()
		return d
	}

	for i, permitted := range e.restricted.Commands {
		if !matchRestrictedCommand(permitted, argv) {
			continue
		}
		d.Action = control.FilterActionAllowAndLog
		d.Matched = true
		d.RuleIndex = i
		d.Detail = fmt.Sprintf("restricted_exec.commands[%d] (%s) permits it", i, permitted.Executable)
		return d
	}

	d.Action = control.FilterActionBlockCommand
	d.Detail = fmt.Sprintf("no permitted command covers argv %q", argv)
	return d
}

// matchRestrictedCommand reports whether one entry of the permitted list covers
// the whole vector.
func matchRestrictedCommand(c control.RestrictedCommand, argv []string) bool {
	if len(argv) == 0 || argv[0] != c.Executable {
		return false
	}
	args := argv[1:]
	switch c.Form {
	case control.CommandFormExact:
		if len(args) != len(c.Argv) {
			return false
		}
		for i, want := range c.Argv {
			if args[i] != want {
				return false
			}
		}
		return true
	case control.CommandFormPositional:
		// An argument past the last spec is uncovered, and uncovered is denied:
		// there is no trailing allowance.
		if len(args) > len(c.Args) {
			return false
		}
		for i, spec := range c.Args {
			if i >= len(args) {
				// Validation guarantees every spec after an optional one is
				// optional too, so the first absent position decides the rest.
				return spec.Optional
			}
			if !matchArgument(spec, args[i]) {
				return false
			}
		}
		return true
	default:
		// Unreachable: New refuses a policy with an unknown form. Denying is
		// the only reading of "this shape is unknown" that keeps the boundary.
		return false
	}
}

// matchArgument reports whether one argument fits the shape the server wrote
// for its position.
func matchArgument(spec control.ArgumentSpec, arg string) bool {
	switch spec.Kind {
	case control.ArgumentLiteral:
		return arg == spec.Value
	case control.ArgumentPrefix:
		return strings.HasPrefix(arg, spec.Value)
	case control.ArgumentOneOf:
		for _, v := range spec.Values {
			if arg == v {
				return true
			}
		}
		return false
	case control.ArgumentAny:
		return true
	default:
		return false
	}
}
