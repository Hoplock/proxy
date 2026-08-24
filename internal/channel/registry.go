// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package channel

import "sync"

// AnyChannel registers an inspector for every channel type. Its inspectors run
// after the ones registered for the specific type, so a recorder that wants
// every channel does not get in front of a filter that wants one.
const AnyChannel = "*"

// Registry maps channel types to their ordered inspector chains.
//
// It is built once, from config and policy, and shared by every session on the
// proxy: an inspector is a stateless decider, and per-session state belongs in
// the Inspection the pipeline hands back. Registration order is the chain
// order, which is the whole point — a specific rule placed before a broad one
// has to decide first (PLAN §6.3).
//
// The zero Registry is not usable; a nil *Registry is, and registers nothing,
// which is what a proxy with no inspectors configured passes in.
type Registry struct {
	mu     sync.RWMutex
	byType map[string][]Inspector
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{byType: make(map[string][]Inspector)}
}

// Register appends inspectors to a channel type's chain, in order. Use
// AnyChannel for a chain that applies to every channel type.
func (r *Registry) Register(channelType string, inspectors ...Inspector) {
	if r == nil || len(inspectors) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.byType == nil {
		r.byType = make(map[string][]Inspector)
	}
	r.byType[channelType] = append(r.byType[channelType], inspectors...)
}

// Inspectors returns the chain for a channel type: the inspectors registered
// for it, followed by those registered for AnyChannel. It returns nil when
// there are none, which is the case the pipeline's pass-through path tests for.
func (r *Registry) Inspectors(channelType string) []Inspector {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()

	specific, any := r.byType[channelType], r.byType[AnyChannel]
	if channelType == AnyChannel {
		any = nil // do not list the wildcard chain twice
	}
	if len(specific)+len(any) == 0 {
		return nil
	}
	chain := make([]Inspector, 0, len(specific)+len(any))
	chain = append(chain, specific...)
	chain = append(chain, any...)
	return chain
}
