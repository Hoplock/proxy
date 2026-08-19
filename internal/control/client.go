// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package control

import "context"

// Client is every conversation the proxy has with Hoplock Control. No
// other package may talk to the server directly (PLAN §3): they depend on this
// interface, which keeps the proxy testable against the mock server and lets
// a later phase swap REST for a streaming transport without touching callers.
//
// Error contract, uniform across all methods:
//   - a deny decision returns an error satisfying IsUnauthorized;
//   - transport failures wrap ErrTransport, server failures ErrServer, and
//     contract violations ErrProtocol.
//
// A caller must therefore never treat "any error" as a deny, and never treat a
// non-deny error as permission to continue (D2: fail closed).
type Client interface {
	// AuthenticateCert relays a public key or certificate offered by the client.
	// A successful response always has Status AuthStatusAuthenticated.
	AuthenticateCert(ctx context.Context, req *AuthenticateCertRequest) (*AuthenticateResponse, error)

	// AuthenticatePassword relays a password. The response may be
	// AuthStatusMFARequired, in which case the caller polls PollMFA with the
	// returned challenge until it resolves.
	AuthenticatePassword(ctx context.Context, req *AuthenticatePasswordRequest) (*AuthenticateResponse, error)

	// PollMFA polls an outstanding MFA challenge. It returns
	// AuthStatusMFARequired while the user has not answered, an authenticated
	// response on approval, and a deny on refusal or expiry.
	PollMFA(ctx context.Context, req *MFAPollRequest) (*AuthenticateResponse, error)

	// Authorize turns an authenticated identity plus a requested target into the
	// complete policy for the connection: route, channels, and filter policy.
	Authorize(ctx context.Context, req *AuthorizeRequest) (*AuthorizeResponse, error)

	// ReportHostKey reports a target host key and returns the trust decision
	// for it (D7).
	ReportHostKey(ctx context.Context, req *HostKeyReportRequest) (*HostKeyReportResponse, error)

	// IngestLogBatch ships accumulated log records on the throughput path (D8).
	IngestLogBatch(ctx context.Context, req *LogBatchRequest) (*LogBatchResponse, error)

	// IngestPriorityLog ships one critical record on the low-latency path and
	// returns only once the server reports it durable (D8).
	IngestPriorityLog(ctx context.Context, req *LogPriorityRequest) (*LogPriorityResponse, error)
}
