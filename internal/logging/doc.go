// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

// Package logging is the proxy's telemetry pipeline (PLAN §7, D8).
//
// It has three layers, and the seam between them is what makes each one
// testable on its own:
//
//   - A [SessionRecorder] turns what happened on one session into
//     [control.LogRecord]s. It owns the record SCHEMA — the kinds, the
//     severities, and the attribute keys a security team writes queries
//     against — and nothing else. It never touches the network or the disk.
//   - A [Shipper] delivers records. Ordinary telemetry accumulates into a
//     batch and goes to Hoplock Control's batch endpoint on a size or interval
//     trigger; a critical record flushes the in-flight batch and then takes the
//     dedicated priority endpoint, so a blocked command is at the server before
//     the batch it would otherwise have waited in (D8).
//   - A disk buffer catches everything the Shipper could not deliver, one area
//     per session, and drains it in order when Hoplock Control comes back.
//     Local disk is a buffer and never the destination (PLAN §7).
//
// Redaction is structural rather than a filter: the recorder is only ever
// handed what a capture point chose to give it, and no capture point is given
// the initial-auth password. The password a user types DURING a session is
// captured, because it is already compromised and must be rotated (PLAN §7).
package logging
