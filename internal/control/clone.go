// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package control

import "time"

// Deep copies of the policy payloads.
//
// A decision is handed to a session, and a cached decision is handed to many.
// Nothing a session is given may share backing memory with what the cache — or
// another session — holds, or one connection could rewrite another's policy
// through a slice it was handed. Every mutable field (slice, map, pointer) is
// therefore copied here, and there is exactly one implementation so that the
// cache (internal/control) and the route (internal/routing) cannot drift into
// two almost-correct copies.
//
// The rule when adding a field to any of these types: if it is a slice, a map,
// or a pointer, it needs a line here and a case in a mutation test —
// TestCloneIsolatesEveryMutableField in policy_test.go for the v2 vocabulary,
// TestCloneIsolatesTheLadder in ladder_test.go for v3. Missing one is silent
// until two sessions collide.

func cloneStrings(in []string) []string {
	if in == nil {
		return nil
	}
	return append([]string(nil), in...)
}

// Clone deep-copies an in-channel request policy.
func (p *RequestPolicy) Clone() *RequestPolicy {
	if p == nil {
		return nil
	}
	return &RequestPolicy{
		Types:      cloneStrings(p.Types),
		Subsystems: cloneStrings(p.Subsystems),
	}
}

// Clone deep-copies a forwarding destination policy.
func (p *ForwardPolicy) Clone() *ForwardPolicy {
	if p == nil {
		return nil
	}
	return &ForwardPolicy{
		DirectTCPIP:    cloneDestinations(p.DirectTCPIP),
		ForwardedTCPIP: cloneDestinations(p.ForwardedTCPIP),
	}
}

func cloneDestinations(in []ForwardDestination) []ForwardDestination {
	if in == nil {
		return nil
	}
	out := make([]ForwardDestination, len(in))
	for i, d := range in {
		out[i] = d
		if d.PortRange != nil {
			pr := *d.PortRange
			out[i].PortRange = &pr
		}
	}
	return out
}

// Clone deep-copies a global request policy.
func (p *GlobalRequestPolicy) Clone() *GlobalRequestPolicy {
	if p == nil {
		return nil
	}
	return &GlobalRequestPolicy{Types: cloneStrings(p.Types)}
}

// Clone deep-copies a target credential selection, parameters included.
func (a *TargetAuth) Clone() *TargetAuth {
	if a == nil {
		return nil
	}
	out := &TargetAuth{Method: a.Method}
	if a.Params != nil {
		out.Params = make(map[string]string, len(a.Params))
		for k, v := range a.Params {
			out.Params[k] = v
		}
	}
	return out
}

// Clone deep-copies a credential ladder, entry by entry and parameter by
// parameter.
//
// The ladder is what a session walks to decide which credential it connects
// with, so a cached decision that shared its backing array with a live session
// would let one connection reorder — or rewrite the parameters of — another
// connection's credentials. Nil and empty are kept apart here as carefully as
// they are on the wire: cloning an empty ladder must not produce an absent one,
// because the first denies the session and the second falls back to local
// configuration.
func (l *TargetAuthLadder) Clone() *TargetAuthLadder {
	if l == nil {
		return nil
	}
	out := make(TargetAuthLadder, len(*l))
	for i, entry := range *l {
		out[i] = *entry.Clone()
	}
	return &out
}

// Clone deep-copies a filter policy, both tiers included.
func (p FilterPolicy) Clone() FilterPolicy {
	out := p
	if p.Rules != nil {
		out.Rules = append([]FilterRule(nil), p.Rules...)
	}
	out.RestrictedExec = p.RestrictedExec.Clone()
	return out
}

// Clone deep-copies a restricted exec policy, down to each argument spec.
func (p *RestrictedExecPolicy) Clone() *RestrictedExecPolicy {
	if p == nil {
		return nil
	}
	out := &RestrictedExecPolicy{}
	if p.Commands != nil {
		out.Commands = make([]RestrictedCommand, len(p.Commands))
		for i, c := range p.Commands {
			out.Commands[i] = RestrictedCommand{
				Executable: c.Executable,
				Form:       c.Form,
				Argv:       cloneStrings(c.Argv),
			}
			if c.Args != nil {
				args := make([]ArgumentSpec, len(c.Args))
				for j, a := range c.Args {
					args[j] = a
					args[j].Values = cloneStrings(a.Values)
				}
				out.Commands[i].Args = args
			}
		}
	}
	return out
}

// Clone deep-copies an enforcement policy, destinations and attestation
// included (contract v4).
func (p *EnforcementPolicy) Clone() *EnforcementPolicy {
	if p == nil {
		return nil
	}
	out := *p
	out.PermittedDestinations = cloneDestinations(p.PermittedDestinations)
	out.Attestation = p.Attestation.Clone()
	return &out
}

// Clone deep-copies an attestation.
func (a *Attestation) Clone() *Attestation {
	if a == nil {
		return nil
	}
	out := *a
	out.AssertedAt = cloneTime(a.AssertedAt)
	return &out
}

// Clone deep-copies a grant context.
//
// It matters here as much as anywhere else even though the proxy makes no
// decision from it: a cached decision is handed to many sessions, and every one
// of them copies this into its own log records. One session mutating the map
// another is logging would corrupt an audit trail, which is the one thing in
// this system that cannot be reconstructed afterwards.
func (c *GrantContext) Clone() *GrantContext {
	if c == nil {
		return nil
	}
	out := *c
	out.WindowStart = cloneTime(c.WindowStart)
	out.WindowEnd = cloneTime(c.WindowEnd)
	out.Additional = c.Additional.Clone()
	return &out
}

// Clone deep-copies an additional-context payload, whichever form it took.
func (c *AdditionalContext) Clone() *AdditionalContext {
	if c == nil {
		return nil
	}
	out := &AdditionalContext{Text: c.Text}
	if c.Fields != nil {
		fields, _ := cloneJSONValue(c.Fields).(map[string]any)
		out.Fields = fields
	}
	return out
}

// cloneJSONValue deep-copies a decoded JSON value. The object form of
// additional_context is arbitrary and nested — the systems on the other end of
// a grant differ more than a fixed schema can absorb — so a one-level copy of
// the top map would still let two sessions share a nested one.
func cloneJSONValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, item := range t {
			out[k] = cloneJSONValue(item)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, item := range t {
			out[i] = cloneJSONValue(item)
		}
		return out
	default:
		// Strings, numbers, booleans and nil are values; nothing aliases.
		return v
	}
}

// Clone deep-copies concurrency limits.
func (l *ConcurrencyLimits) Clone() *ConcurrencyLimits {
	if l == nil {
		return nil
	}
	out := *l
	return &out
}

// Clone deep-copies the proxy's declared capabilities.
func (c *ProxyCapabilities) Clone() *ProxyCapabilities {
	if c == nil {
		return nil
	}
	out := &ProxyCapabilities{}
	if c.Execution != nil {
		out.Execution = append([]ExecutionRung(nil), c.Execution...)
	}
	if c.Reach != nil {
		out.Reach = append([]ReachRung(nil), c.Reach...)
	}
	return out
}

// Clone deep-copies an observed target capability record.
func (c *TargetCapabilities) Clone() *TargetCapabilities {
	if c == nil {
		return nil
	}
	out := *c
	if c.Execution != nil {
		out.Execution = append([]ExecutionRung(nil), c.Execution...)
	}
	if c.Reach != nil {
		out.Reach = append([]ReachRung(nil), c.Reach...)
	}
	if c.Detail != nil {
		out.Detail = make(map[string]string, len(c.Detail))
		for k, v := range c.Detail {
			out.Detail[k] = v
		}
	}
	return &out
}

// cloneTime copies an optional instant. time.Time is a value, so only the
// pointer needs breaking.
func cloneTime(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	out := *t
	return &out
}

// Clone deep-copies hop metadata.
func (h *HopMetadata) Clone() *HopMetadata {
	if h == nil {
		return nil
	}
	out := *h
	out.HopTrail = cloneStrings(h.HopTrail)
	return &out
}

// Clone deep-copies a cache hint.
func (h *CacheHint) Clone() *CacheHint {
	if h == nil {
		return nil
	}
	out := *h
	return &out
}

// Clone deep-copies a whole authorize decision. It is what stands between a
// cached policy and a caller that mutates the slice it was handed.
func (r *AuthorizeResponse) Clone() *AuthorizeResponse {
	if r == nil {
		return nil
	}
	out := *r
	out.PermittedChannels = cloneStrings(r.PermittedChannels)
	out.PermittedRequests = r.PermittedRequests.Clone()
	out.PermittedForwards = r.PermittedForwards.Clone()
	out.PermittedGlobalRequests = r.PermittedGlobalRequests.Clone()
	out.TargetAuth = r.TargetAuth.Clone()
	out.TargetAuthLadder = r.TargetAuthLadder.Clone()
	out.FilterPolicy = r.FilterPolicy.Clone()
	out.Enforcement = r.Enforcement.Clone()
	out.SessionDeadline = cloneTime(r.SessionDeadline)
	out.GrantContext = r.GrantContext.Clone()
	out.Concurrency = r.Concurrency.Clone()
	out.Hop = r.Hop.Clone()
	out.Cache = r.Cache.Clone()
	return &out
}
