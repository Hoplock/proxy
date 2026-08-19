// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package control

import (
	"errors"
	"fmt"
)

// Sentinel causes, wrapped by APIError so callers classify a failure with
// errors.Is instead of comparing status codes or matching strings.
var (
	// ErrUnauthorized is a deny *decision* from the server (HTTP 401): the
	// credential was rejected, or the identity may not reach the target. It is
	// never returned for a transport or server failure, so a caller must not
	// fail open on any other error.
	ErrUnauthorized = errors.New("denied by Hoplock Control")
	// ErrBadRequest means the server rejected the request as malformed (4xx
	// other than 401) — a bug in the caller, not a policy decision.
	ErrBadRequest = errors.New("request rejected by Hoplock Control")
	// ErrServer means the server failed to process a valid request (5xx).
	ErrServer = errors.New("failure inside Hoplock Control")
	// ErrTransport means the call never produced a usable HTTP response
	// (dial failure, timeout, cancelled context, TLS failure).
	ErrTransport = errors.New("could not reach Hoplock Control")
	// ErrProtocol means a response was received but did not match the contract
	// (undecodable body, missing required field, unknown enum value).
	ErrProtocol = errors.New("response from Hoplock Control violates the contract")
)

// APIError describes one failed Control API call. Op is the client method
// that failed, so an error read in a log names the call without a stack trace.
type APIError struct {
	// Op is the failing operation, e.g. "Authorize".
	Op string
	// StatusCode is the HTTP status, or 0 when no response was received.
	StatusCode int
	// Code is the machine-readable code from the server's error body, if any.
	Code string
	// Message is the server's human-readable detail, if any.
	Message string
	// Cause is the sentinel this error classifies as, optionally wrapping the
	// underlying transport or decoding error.
	Cause error
}

func (e *APIError) Error() string {
	msg := fmt.Sprintf("control %s: %v", e.Op, e.Cause)
	if e.StatusCode != 0 {
		msg += fmt.Sprintf(" (http %d", e.StatusCode)
		if e.Code != "" {
			msg += ", code " + e.Code
		}
		msg += ")"
	}
	if e.Message != "" {
		msg += ": " + e.Message
	}
	return msg
}

// Unwrap exposes the cause chain to errors.Is and errors.As.
func (e *APIError) Unwrap() error { return e.Cause }

// IsUnauthorized reports whether err is a deny decision from the server, as
// opposed to a transport or server failure. Callers that must not fail open
// should use this rather than testing for "any error".
func IsUnauthorized(err error) bool { return errors.Is(err, ErrUnauthorized) }

// errorBody is the contract's error envelope: {"error":{"code","message"}}.
type errorBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}
