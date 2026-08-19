// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

// Package sshtest provides an in-process SSH server that stands in for a target
// host, plus the key helpers tests need around it.
//
// It exists because the proxy has two ends and both have to be real for a test
// to prove anything: a fake that returns canned bytes would not exercise channel
// opens, request replies, exit statuses, or teardown, which is where a proxy's
// bugs live. Two test packages need the same target — the engine's own tests and
// the end-to-end test that drives the mock Hoplock Control — so it is a
// package rather than a helper duplicated in each.
//
// It is test support: it authenticates anyone, and nothing here belongs in a
// deployment. The containerised sshd of the full topology (phase 0011) replaces
// it for scenario testing; this one keeps the unit and integration tests
// hermetic and fast.
package sshtest
