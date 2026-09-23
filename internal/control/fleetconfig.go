// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// This file is phase 0042: how Hoplock Control distributes configuration to a
// fleet, and how a proxy answers (PLAN D18).
//
// Three rules shape it, and each is a reason something is NOT done here:
//
//   - The event is a notification, never the document. The revocation stream
//     is replayable from a last_event_id, so a document carried inline would be
//     replayed — and a replayed configuration is a stale one applied as if it
//     were current. The proxy therefore fetches the CURRENT document whenever it
//     is told something moved, and a replayed notification can at worst cause a
//     fetch that answers "not modified".
//   - Running means running. A document is reported as the running version only
//     when every setting in it is in force in this process; one that needs a
//     restart is held and reported as pending, so Control's drift view cannot
//     say a rollout finished when it has not.
//   - Configuration is not on the data path. Nothing here ends a session,
//     refuses a connection, or touches a cached decision: a document that
//     cannot be fetched, parsed, or applied leaves the proxy serving on the last
//     one that could, and says so.

// PathProxyConfig is the proxy's desired configuration document, templated on
// the proxy id. Build a concrete path with ProxyConfigPath.
const PathProxyConfig = "/v1/proxies/{proxy_id}/config"

// PathProxyConfigReport is where the proxy says which document it is running,
// templated on the proxy id. Build a concrete path with ProxyConfigReportPath.
const PathProxyConfigReport = "/v1/proxies/{proxy_id}/config/report"

// ProxyConfigPath returns the configuration document path for one proxy.
func ProxyConfigPath(proxyID string) string {
	return "/v1/proxies/" + url.PathEscape(proxyID) + "/config"
}

// ProxyConfigReportPath returns the configuration report path for one proxy.
func ProxyConfigReportPath(proxyID string) string {
	return ProxyConfigPath(proxyID) + "/report"
}

// ErrConfigNotModified is returned by FetchProxyConfig when the server answered
// 304: the document the proxy already holds is still the desired one.
var ErrConfigNotModified = errors.New("configuration document not modified")

// ConfigChangedEvent says that the proxy's desired configuration moved. It
// names the document; it does not carry it (see the file comment).
type ConfigChangedEvent struct {
	// Version is Control's name for the desired document, opaque to the proxy.
	Version string `json:"version"`
	// Hash is Control's content identifier for the document. The proxy compares
	// it for equality and never computes or parses it.
	Hash string `json:"hash"`
}

// ProxyConfigDocument is one desired configuration, as fetched from
// GET /v1/proxies/{proxy_id}/config.
//
// The zero value — no version, no hash, no settings — is what a 204 means:
// nothing is published for this proxy, so it runs on its bootstrap file alone.
// Read that through Published rather than by testing fields.
type ProxyConfigDocument struct {
	// Version is Control's name for the document.
	Version string `json:"version"`
	// Hash is Control's content identifier for the document; it is also the
	// response's ETag, and the proxy sends it back as If-None-Match.
	Hash string `json:"hash"`
	// Settings maps a fleet-owned setting, by its dotted bootstrap key (for
	// example "control.cache.max_ttl"), to its value. The document is applied
	// whole or not at all: a key that is not fleet-owned, or a value that does
	// not validate, rejects the entire document.
	Settings map[string]json.RawMessage `json:"settings"`
}

// Published reports whether the document is a real one rather than the "nothing
// published" answer.
func (d *ProxyConfigDocument) Published() bool { return d != nil && d.Version != "" }

// Ref returns the document's identity.
func (d *ProxyConfigDocument) Ref() ConfigRef {
	if d == nil {
		return ConfigRef{}
	}
	return ConfigRef{Version: d.Version, Hash: d.Hash}
}

// ConfigRef names a document by version and hash. The zero value names the
// bootstrap file alone.
type ConfigRef struct {
	Version string `json:"version,omitempty"`
	Hash    string `json:"hash,omitempty"`
}

// IsZero reports whether r names no document.
func (r ConfigRef) IsZero() bool { return r.Version == "" && r.Hash == "" }

// ConfigState is what a proxy says about its desired document.
type ConfigState string

const (
	// ConfigStateApplied: the desired document is the running one — every
	// setting in it is in force in this process.
	ConfigStateApplied ConfigState = "applied"
	// ConfigStatePendingRestart: the desired document is valid, but at least one
	// setting it changes takes effect only when the process restarts. Nothing
	// from it has been applied; the running document is unchanged.
	ConfigStatePendingRestart ConfigState = "pending_restart"
	// ConfigStateRejected: the desired document could not be parsed or applied.
	// The proxy keeps serving on its running document.
	ConfigStateRejected ConfigState = "rejected"
	// ConfigStateFetchFailed: the proxy was told its desired document moved and
	// could not fetch it. It keeps serving on its running document and retries.
	ConfigStateFetchFailed ConfigState = "fetch_failed"
)

// ProxyConfigReport is the body of POST /v1/proxies/{proxy_id}/config/report.
type ProxyConfigReport struct {
	// RunningVersion and RunningHash name the document every setting of which is
	// in force in this process. Both absent means the proxy is running on its
	// bootstrap file alone.
	RunningVersion string `json:"running_version,omitempty"`
	RunningHash    string `json:"running_hash,omitempty"`
	// DesiredVersion and DesiredHash name the newest document the proxy knows
	// of — fetched, or announced by an event it could not follow up. Both absent
	// means none is published.
	DesiredVersion string `json:"desired_version,omitempty"`
	DesiredHash    string `json:"desired_hash,omitempty"`
	// State says what became of the desired document.
	State ConfigState `json:"state"`
	// RestartRequired lists the settings that keep a pending_restart document
	// from applying. Absent otherwise.
	RestartRequired []string `json:"restart_required,omitempty"`
	// LastError says why a document was rejected or could not be fetched. It
	// never contains a setting's value, only its key.
	LastError string `json:"last_error,omitempty"`
	// ReportedAt is when the proxy reached this state.
	ReportedAt time.Time `json:"reported_at"`
}

// ProxyConfigReportResponse acknowledges a report.
type ProxyConfigReportResponse struct {
	// Accepted is true when the server recorded the report.
	Accepted bool `json:"accepted"`
}

// FleetConfigSource is the proxy's half of fleet configuration. It is not on
// Client for the reason CapabilityReporter is not: one caller, and every other
// holder of a Client would only grow a stub. CachingClient deliberately does
// not implement it — a configuration document answered from memory is the
// stale document this file exists not to apply.
type FleetConfigSource interface {
	// FetchProxyConfig fetches the proxy's desired document. ifNoneMatch is the
	// hash of the document the proxy already holds, or "". It returns
	// ErrConfigNotModified when that is still the desired one, and the zero
	// document when nothing is published.
	FetchProxyConfig(ctx context.Context, proxyID, ifNoneMatch string) (*ProxyConfigDocument, error)
	// ReportProxyConfig says which document the proxy is running.
	ReportProxyConfig(ctx context.Context, proxyID string, report *ProxyConfigReport) (*ProxyConfigReportResponse, error)
}

var _ FleetConfigSource = (*RESTClient)(nil)

// FetchProxyConfig implements FleetConfigSource.
func (c *RESTClient) FetchProxyConfig(ctx context.Context, proxyID, ifNoneMatch string) (*ProxyConfigDocument, error) {
	const op = "FetchProxyConfig"
	if proxyID == "" {
		return nil, &APIError{Op: op, Cause: fmt.Errorf("%w: proxy id is required", ErrBadRequest)}
	}
	if c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL.String()+ProxyConfigPath(proxyID), nil)
	if err != nil {
		return nil, &APIError{Op: op, Cause: fmt.Errorf("%w: build request: %v", ErrTransport, err)}
	}
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("User-Agent", c.userAgent)
	if c.token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.token)
	}
	if ifNoneMatch != "" {
		httpReq.Header.Set("If-None-Match", quoteETag(ifNoneMatch))
	}

	httpResp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, &APIError{Op: op, Cause: fmt.Errorf("%w: %w", ErrTransport, err)}
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(httpResp.Body, maxErrorBodyBytes))
		_ = httpResp.Body.Close()
	}()

	switch httpResp.StatusCode {
	case http.StatusOK:
	case http.StatusNoContent:
		return &ProxyConfigDocument{}, nil
	case http.StatusNotModified:
		return nil, &APIError{Op: op, StatusCode: http.StatusNotModified, Cause: ErrConfigNotModified}
	default:
		return nil, statusError(op, httpResp)
	}

	var doc ProxyConfigDocument
	if err := json.NewDecoder(io.LimitReader(httpResp.Body, maxEventLineBytes)).Decode(&doc); err != nil {
		return nil, protocolError(op, fmt.Errorf("decode response: %v", err))
	}
	if doc.Version == "" || doc.Hash == "" {
		// A 200 is a published document; the "nothing published" answer is a
		// 204. A document without a name is one the proxy could neither report
		// nor tell apart from the next.
		return nil, protocolError(op, errors.New("document has no version or hash"))
	}
	return &doc, nil
}

// ReportProxyConfig implements FleetConfigSource.
func (c *RESTClient) ReportProxyConfig(ctx context.Context, proxyID string, report *ProxyConfigReport) (*ProxyConfigReportResponse, error) {
	const op = "ReportProxyConfig"
	if proxyID == "" {
		return nil, &APIError{Op: op, Cause: fmt.Errorf("%w: proxy id is required", ErrBadRequest)}
	}
	resp, err := post[ProxyConfigReportResponse](ctx, c, op, ProxyConfigReportPath(proxyID), report, http.StatusOK)
	if err != nil {
		return nil, err
	}
	if !resp.Accepted {
		return nil, protocolError(op, errors.New("server did not accept the configuration report"))
	}
	return resp, nil
}

// quoteETag renders a hash as an HTTP entity tag. A hash that is already quoted
// is sent as it is.
func quoteETag(h string) string {
	if strings.HasPrefix(h, `"`) || strings.HasPrefix(h, `W/"`) {
		return h
	}
	return `"` + h + `"`
}
