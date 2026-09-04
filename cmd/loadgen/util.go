// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package main

import (
	"net"
	"strconv"
	"strings"
	"syscall"
)

// tail returns the last n non-empty lines of s.
func tail(s string, n int) string {
	lines := make([]string, 0, 32)
	for _, l := range splitLines(s) {
		if strings.TrimSpace(l) != "" {
			lines = append(lines, l)
		}
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func splitLines(s string) []string {
	return strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
}

// cutColon splits "key:   value" into its trimmed halves.
func cutColon(line string) (key, value string, ok bool) {
	k, v, found := strings.Cut(line, ":")
	if !found {
		return "", "", false
	}
	return strings.TrimSpace(k), strings.TrimSpace(v), true
}

func splitHostPort(addr string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, err
	}
	return host, port, nil
}

// freeLoopbackAddr reserves a loopback port and releases it, so the proxy can
// bind it. There is a race in principle; on a machine running one load test
// there is not one in practice, and the alternative is a fixed port that
// collides with whatever else the developer left running.
func freeLoopbackAddr() (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	addr := ln.Addr().String()
	return addr, ln.Close()
}

// fdLimit reports this process's soft descriptor limit. The proxy inherits it,
// which is what makes it the right number to compare a peak descriptor count
// against.
func fdLimit() uint64 {
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		return 0
	}
	return lim.Cur
}
