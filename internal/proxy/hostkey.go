// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package proxy

import (
	"errors"
	"fmt"
	"net"

	"golang.org/x/crypto/ssh"

	"github.com/mauroasilva/securecommandproxy/internal/mgmt"
)

// ErrHostKeyRejected means the management server refused the target's host key.
var ErrHostKeyRejected = errors.New("proxy: target host key rejected by the management server")

// hostKeyCallback implements the prototype's host-key policy: trust on first
// use, but report every key to the management server (D7).
//
// The bastion keeps no known-hosts file of its own. That is deliberate: a local
// trust store would be a second policy, diverging per bastion, in a system whose
// whole premise is that decisions are central (D2). Reporting on every
// connection costs one round trip at setup and gives the server the evidence it
// needs to move from trust-on-first-use to per-target pinning later, without a
// bastion change.
func (s *session) hostKeyCallback(_ string, remote net.Addr, key ssh.PublicKey) error {
	resp, err := s.srv.client.ReportHostKey(s.ctx, &mgmt.HostKeyReportRequest{
		Target:     s.route.Host,
		TargetPort: s.route.Port,
		HostKey:    hostKeyMaterial(key),
		Conn:       s.connMeta(),
	})
	if err != nil {
		// Failing closed: an unverifiable host key is exactly the case a
		// man-in-the-middle produces, so an unreachable server must not become
		// "carry on".
		return s.recordHostKeyErr(fmt.Errorf("report host key: %w", err))
	}
	if resp.Decision != mgmt.HostKeyAccept {
		return s.recordHostKeyErr(fmt.Errorf("%w (%s)", ErrHostKeyRejected, resp.Reason))
	}
	if !resp.Known {
		s.logf("proxy: session=%s target=%s host key %s trusted on first use, reported to the management server",
			s.id, remote, ssh.FingerprintSHA256(key))
	}
	return nil
}

// recordHostKeyErr keeps the reason the handshake is about to fail, because the
// error x/crypto returns from Dial is its own rendering and the engine needs
// the original to classify deny-versus-outage (PLAN §4.3).
func (s *session) recordHostKeyErr(err error) error {
	s.mu.Lock()
	s.hostKeyErr = err
	s.mu.Unlock()
	return err
}

func (s *session) takeHostKeyErr() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hostKeyErr
}

// hostKeyMaterial converts a host key to its wire form. Nothing is validated
// locally, for the same reason user certificates are not (D2).
func hostKeyMaterial(key ssh.PublicKey) mgmt.PublicKeyMaterial {
	_, isCert := key.(*ssh.Certificate)
	return mgmt.PublicKeyMaterial{
		Type:          key.Type(),
		Blob:          key.Marshal(),
		Fingerprint:   ssh.FingerprintSHA256(key),
		IsCertificate: isCert,
	}
}
