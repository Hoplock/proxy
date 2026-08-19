// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package control

import (
	"bytes"
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

// DefaultTimeout bounds a single Control API call when Options.Timeout is
// left zero. Every call is on a session's critical path, so waiting forever is
// never the right behaviour.
const DefaultTimeout = 10 * time.Second

// defaultUserAgent identifies the proxy's client to the server.
const defaultUserAgent = "hoplock-proxy/1"

// maxErrorBodyBytes caps how much of an error response we read before giving
// up, so a misbehaving or hostile server cannot make the proxy buffer without
// bound on a failure path.
const maxErrorBodyBytes = 64 << 10

// Options configures a RESTClient.
type Options struct {
	// BaseURL is Hoplock Control root, e.g. "https://control.example.com".
	// Required; taken from the proxy's bootstrap config.
	BaseURL string
	// Token authenticates the proxy to Hoplock Control as a bearer
	// token. This is the seam for the proxy→server channel credential: a
	// deployment may replace it with mTLS by supplying its own HTTPClient.
	Token string
	// HTTPClient is used for all calls. When nil a client with sane transport
	// defaults is built.
	HTTPClient *http.Client
	// Timeout bounds each call. Zero means DefaultTimeout; negative disables
	// the client-side deadline and leaves the bound to the caller's context.
	Timeout time.Duration
	// UserAgent overrides the User-Agent header.
	UserAgent string
}

// RESTClient is the JSON-over-HTTPS implementation of Client (D9).
type RESTClient struct {
	baseURL   *url.URL
	token     string
	http      *http.Client
	timeout   time.Duration
	userAgent string
}

var _ Client = (*RESTClient)(nil)

// NewRESTClient validates opts and returns a client for the Control API.
func NewRESTClient(opts Options) (*RESTClient, error) {
	if opts.BaseURL == "" {
		return nil, errors.New("control: BaseURL is required")
	}
	u, err := url.Parse(opts.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("control: parse BaseURL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("control: BaseURL scheme %q must be http or https", u.Scheme)
	}
	if u.Host == "" {
		return nil, errors.New("control: BaseURL has no host")
	}
	// Paths are absolute, so a base path must not silently swallow them.
	u.Path = strings.TrimSuffix(u.Path, "/")

	c := &RESTClient{
		baseURL:   u,
		token:     opts.Token,
		http:      opts.HTTPClient,
		timeout:   opts.Timeout,
		userAgent: opts.UserAgent,
	}
	if c.http == nil {
		c.http = &http.Client{}
	}
	if c.timeout == 0 {
		c.timeout = DefaultTimeout
	}
	if c.userAgent == "" {
		c.userAgent = defaultUserAgent
	}
	return c, nil
}

// AuthenticateCert implements Client.
func (c *RESTClient) AuthenticateCert(ctx context.Context, req *AuthenticateCertRequest) (*AuthenticateResponse, error) {
	const op = "AuthenticateCert"
	resp, err := post[AuthenticateResponse](ctx, c, op, PathAuthenticateCert, req, http.StatusOK)
	if err != nil {
		return nil, err
	}
	if err := validateAuthResponse(op, resp); err != nil {
		return nil, err
	}
	if resp.Status != AuthStatusAuthenticated {
		return nil, protocolError(op, fmt.Errorf("status %q: certificate auth never requires MFA", resp.Status))
	}
	return resp, nil
}

// AuthenticatePassword implements Client.
func (c *RESTClient) AuthenticatePassword(ctx context.Context, req *AuthenticatePasswordRequest) (*AuthenticateResponse, error) {
	const op = "AuthenticatePassword"
	resp, err := post[AuthenticateResponse](ctx, c, op, PathAuthenticatePassword, req, http.StatusOK)
	if err != nil {
		return nil, err
	}
	if err := validateAuthResponse(op, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// PollMFA implements Client.
func (c *RESTClient) PollMFA(ctx context.Context, req *MFAPollRequest) (*AuthenticateResponse, error) {
	const op = "PollMFA"
	resp, err := post[AuthenticateResponse](ctx, c, op, PathPollMFA, req, http.StatusOK)
	if err != nil {
		return nil, err
	}
	if err := validateAuthResponse(op, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// Authorize implements Client.
func (c *RESTClient) Authorize(ctx context.Context, req *AuthorizeRequest) (*AuthorizeResponse, error) {
	const op = "Authorize"
	resp, err := post[AuthorizeResponse](ctx, c, op, PathAuthorize, req, http.StatusOK)
	if err != nil {
		return nil, err
	}
	switch resp.RouteType {
	case RouteTypeDirect, RouteTypeNextHop:
	default:
		return nil, protocolError(op, fmt.Errorf("unknown route_type %q", resp.RouteType))
	}
	if resp.Target == "" {
		return nil, protocolError(op, errors.New("route has no target"))
	}
	switch resp.FilterPolicy.Mode {
	case FilterModeWhitelist, FilterModeBlacklist:
	default:
		return nil, protocolError(op, fmt.Errorf("unknown filter mode %q", resp.FilterPolicy.Mode))
	}
	for i, rule := range resp.FilterPolicy.Rules {
		if rule.Match == "" {
			return nil, protocolError(op, fmt.Errorf("filter rule %d has no match pattern", i))
		}
		switch rule.Action {
		case FilterActionAllowAndLog, FilterActionBlockCommand, FilterActionWarnAndContinue, FilterActionKillSession:
		default:
			return nil, protocolError(op, fmt.Errorf("filter rule %d (%q): unknown action %q", i, rule.Match, rule.Action))
		}
	}
	if c := resp.Cache; c != nil {
		// A cache hint the proxy cannot honour exactly is refused rather than
		// guessed at: it may not invent a key, and a negative lifetime has no
		// meaning. Either would put the PEP in charge of the decision's
		// lifetime, which is what the server-set TTL exists to prevent.
		if c.TTLSeconds < 0 {
			return nil, protocolError(op, fmt.Errorf("cache.ttl_seconds %d is negative", c.TTLSeconds))
		}
		if c.TTLSeconds > 0 && c.Key == "" {
			return nil, protocolError(op, errors.New("cache.ttl_seconds is set but cache.key is empty"))
		}
	}
	return resp, nil
}

// StreamEvents opens the proxy's revocation stream and returns the events as
// they arrive. It implements EventStreamer.
//
// The call is deliberately outside the per-call timeout: the response is
// long-lived by design, so its only bound is ctx. lastEventID is the last event
// the proxy processed, echoed back so the server can replay the gap; pass ""
// on a first subscription.
func (c *RESTClient) StreamEvents(ctx context.Context, proxyID, lastEventID string) (EventStream, error) {
	const op = "StreamEvents"
	if proxyID == "" {
		return nil, &APIError{Op: op, Cause: fmt.Errorf("%w: proxy id is required", ErrBadRequest)}
	}

	u := c.baseURL.String() + ProxyEventsPath(proxyID)
	if lastEventID != "" {
		u += "?" + url.Values{QueryLastEventID: []string{lastEventID}}.Encode()
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, &APIError{Op: op, Cause: fmt.Errorf("%w: build request: %v", ErrTransport, err)}
	}
	httpReq.Header.Set("Accept", contentTypeNDJSON)
	httpReq.Header.Set("User-Agent", c.userAgent)
	if c.token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.token)
	}

	httpResp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, &APIError{Op: op, Cause: fmt.Errorf("%w: %w", ErrTransport, err)}
	}
	if httpResp.StatusCode != http.StatusOK {
		defer func() {
			_, _ = io.Copy(io.Discard, io.LimitReader(httpResp.Body, maxErrorBodyBytes))
			_ = httpResp.Body.Close()
		}()
		return nil, statusError(op, httpResp)
	}
	return newNDJSONEventStream(httpResp.Body), nil
}

// ReportHostKey implements Client.
func (c *RESTClient) ReportHostKey(ctx context.Context, req *HostKeyReportRequest) (*HostKeyReportResponse, error) {
	const op = "ReportHostKey"
	resp, err := post[HostKeyReportResponse](ctx, c, op, PathReportHostKey, req, http.StatusOK)
	if err != nil {
		return nil, err
	}
	switch resp.Decision {
	case HostKeyAccept, HostKeyReject:
	default:
		return nil, protocolError(op, fmt.Errorf("unknown host key decision %q", resp.Decision))
	}
	return resp, nil
}

// IngestLogBatch implements Client.
func (c *RESTClient) IngestLogBatch(ctx context.Context, req *LogBatchRequest) (*LogBatchResponse, error) {
	const op = "IngestLogBatch"
	if len(req.Records) == 0 {
		return nil, &APIError{Op: op, Cause: fmt.Errorf("%w: batch has no records", ErrBadRequest)}
	}
	return post[LogBatchResponse](ctx, c, op, PathIngestLogBatch, req, http.StatusAccepted)
}

// IngestPriorityLog implements Client.
func (c *RESTClient) IngestPriorityLog(ctx context.Context, req *LogPriorityRequest) (*LogPriorityResponse, error) {
	const op = "IngestPriorityLog"
	resp, err := post[LogPriorityResponse](ctx, c, op, PathIngestPriorityLog, req, http.StatusOK)
	if err != nil {
		return nil, err
	}
	if !resp.Accepted {
		return nil, protocolError(op, errors.New("server did not accept the critical record"))
	}
	return resp, nil
}

// validateAuthResponse enforces the "exactly one of Identity or MFA, per
// Status" rule so callers can dereference without re-checking the contract.
func validateAuthResponse(op string, resp *AuthenticateResponse) error {
	switch resp.Status {
	case AuthStatusAuthenticated:
		if resp.Identity == nil {
			return protocolError(op, errors.New("status authenticated but no identity"))
		}
		if resp.Identity.Subject == "" {
			return protocolError(op, errors.New("identity has no subject"))
		}
	case AuthStatusMFARequired:
		if resp.MFA == nil || resp.MFA.Token == "" {
			return protocolError(op, errors.New("status mfa_required but no challenge token"))
		}
	default:
		return protocolError(op, fmt.Errorf("unknown auth status %q", resp.Status))
	}
	return nil
}

func protocolError(op string, err error) error {
	return &APIError{Op: op, Cause: fmt.Errorf("%w: %v", ErrProtocol, err)}
}

// post marshals req, POSTs it to path, and decodes a wantStatus response into
// Resp. Every failure is returned as an *APIError wrapping a sentinel, so a
// deny is never confused with an outage.
func post[Resp any](ctx context.Context, c *RESTClient, op, path string, req any, wantStatus int) (*Resp, error) {
	body, err := json.Marshal(req)
	if err != nil {
		// Marshalling our own request type failing is a programming error, not
		// something the server said.
		return nil, &APIError{Op: op, Cause: fmt.Errorf("%w: encode request: %v", ErrProtocol, err)}
	}

	if c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL.String()+path, bytes.NewReader(body))
	if err != nil {
		return nil, &APIError{Op: op, Cause: fmt.Errorf("%w: build request: %v", ErrTransport, err)}
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("User-Agent", c.userAgent)
	if c.token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.token)
	}

	httpResp, err := c.http.Do(httpReq)
	if err != nil {
		// Both errors are wrapped: ErrTransport classifies the failure, and the
		// underlying cause stays reachable so a caller can tell a timeout
		// (context.DeadlineExceeded) from a cancellation or a dial failure.
		// url.Error embeds the request URL but never the body, so the password
		// in an auth request cannot reach a log through this path.
		return nil, &APIError{Op: op, Cause: fmt.Errorf("%w: %w", ErrTransport, err)}
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(httpResp.Body, maxErrorBodyBytes))
		_ = httpResp.Body.Close()
	}()

	if httpResp.StatusCode != wantStatus {
		return nil, statusError(op, httpResp)
	}

	var out Resp
	dec := json.NewDecoder(httpResp.Body)
	if err := dec.Decode(&out); err != nil {
		return nil, protocolError(op, fmt.Errorf("decode response: %v", err))
	}
	return &out, nil
}

// statusError classifies an unexpected status and enriches it with the
// server's error envelope when one is present.
func statusError(op string, resp *http.Response) error {
	apiErr := &APIError{Op: op, StatusCode: resp.StatusCode}

	var body errorBody
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxErrorBodyBytes)).Decode(&body); err == nil {
		apiErr.Code = body.Error.Code
		apiErr.Message = body.Error.Message
	}

	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		apiErr.Cause = ErrUnauthorized
	case resp.StatusCode >= 500:
		apiErr.Cause = ErrServer
	case resp.StatusCode >= 400:
		apiErr.Cause = ErrBadRequest
	default:
		// A 2xx/3xx that is not the documented success status is a contract
		// violation: we do not know what the server did.
		apiErr.Cause = fmt.Errorf("%w: unexpected status", ErrProtocol)
	}
	return apiErr
}
