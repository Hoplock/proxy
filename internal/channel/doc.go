// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

// Package channel is the SSH inspection pipeline (PLAN §6.2, D5, D5a).
//
// It owns the three policy axes a session is decided on, each enforced where
// SSH actually decides it:
//
//   - channel types, at the channel open, in both directions;
//   - in-channel requests, at the request rather than at the open, because a
//     session channel is opened before anyone knows whether it is a login, a
//     command, or a file transfer;
//   - forwarding destinations and connection-level global requests, which is
//     where a port forward's whole meaning lives and where a listener is asked
//     for.
//
// Around those axes it hosts an ordered chain of pluggable inspectors per
// channel type, so a filter (0010) or a recorder (0011) can attach without the
// transport core in internal/proxy knowing anything about it. The two are
// deliberately separate: policy comes from Hoplock Control and always runs
// first, inspectors are local code and run after, and neither can be reordered
// into the other.
//
// A channel with no registered inspectors is a straight pass-through: the
// pipeline hands the pump back the very reader it was given, so an
// un-inspected channel costs what phase 0005's direct copy cost.
package channel
