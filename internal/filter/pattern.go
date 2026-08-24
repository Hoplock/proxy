// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package filter

// matchPattern is the guardrail tier's matching rule, and the contract's
// FilterRule.Match semantics (the contract leaves them to this engine).
//
// A pattern matches the WHOLE command, with "*" standing for any run of
// characters and "?" for any one. Anchoring is the decision that matters and it
// is not a detail:
//
//   - Substring matching would make a rule denying "cat /etc/shadow" also deny
//     "sh -c 'cat /etc/shadow'" — and a guardrail that appears to stop the
//     shell wrapper it demonstrably cannot stop is worse than no guardrail,
//     because the estate is then sold a boundary it does not have (D12).
//     Anchoring keeps the tier's limit visible: the wrapper gets past, and the
//     restricted tier is the answer to that, not a cleverer pattern.
//   - Wildcards are needed for the ordering the contract promises: "rm -rf /"
//     placed before "rm *" must decide, and the broad rule behind it has to be
//     writable at all.
//
// Matching is byte-exact and case-sensitive; the command is compared as the
// client sent it, less surrounding whitespace. "/" is not a separator here, so
// "rm *" covers "rm -rf /home/data" — this is a command pattern, not a path
// glob, and path.Match's separator rule would quietly stop a broad rule at the
// first slash.
func matchPattern(pattern, command string) bool {
	// Iterative glob with backtracking: linear in the common case, and it
	// cannot recurse into a stack overflow on a hostile pattern.
	var (
		p, c       int
		star       = -1
		afterStar  int
		patternLen = len(pattern)
		commandLen = len(command)
	)
	for c < commandLen {
		switch {
		case p < patternLen && pattern[p] == '*':
			star, afterStar = p, c
			p++
		case p < patternLen && (pattern[p] == '?' || pattern[p] == command[c]):
			p++
			c++
		case star >= 0:
			// The last "*" was too short: give it one more byte and retry.
			p = star + 1
			afterStar++
			c = afterStar
		default:
			return false
		}
	}
	for p < patternLen && pattern[p] == '*' {
		p++
	}
	return p == patternLen
}
