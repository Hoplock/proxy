// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package relay

import (
	"net"
	"slices"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/sshtest"
)

// These are phase 0049's hub tests: OnChange is what tells Hoplock Control's
// reporter that the set of registered ids moved, so it must fire on every add
// and every removal — however the registration ended — and never on a
// replacement that leaves the set as it was.

// changeLog records what Registrations said each time OnChange fired. The hook
// READS Registrations, which takes the hub's lock: a hook called with the lock
// held would deadlock here and the test would time out, so every passing
// assertion below is also proof that it was called outside h.mu.
type changeLog struct{ sets chan []string }

func watchChanges(t *testing.T, authorized map[string]ssh.PublicKey, tweak func(*HubOptions)) (*testHub, *changeLog, func()) {
	t.Helper()
	log := &changeLog{sets: make(chan []string, 64)}
	var hub *Hub
	h, stop := startHubWith(t, authorized, func(o *HubOptions) {
		o.OnChange = func() { log.sets <- hub.Registrations() }
		if tweak != nil {
			tweak(o)
		}
	})
	hub = h.hub
	return h, log, stop
}

// next is the set the next change left.
func (c *changeLog) next(t *testing.T, what string) []string {
	t.Helper()
	select {
	case set := <-c.sets:
		return set
	case <-time.After(5 * time.Second):
		t.Fatalf("%s: OnChange was not called", what)
		return nil
	}
}

func (c *changeLog) want(t *testing.T, what string, want ...string) {
	t.Helper()
	if want == nil {
		want = []string{}
	}
	if got := c.next(t, what); !slices.Equal(got, want) {
		t.Fatalf("%s: OnChange saw %v, want %v", what, got, want)
	}
}

func (c *changeLog) none(t *testing.T, what string) {
	t.Helper()
	select {
	case set := <-c.sets:
		t.Fatalf("%s: OnChange was called (set %v), and the set did not change", what, set)
	case <-time.After(150 * time.Millisecond):
	}
}

// rawRegistrant registers as id over a bare SSH client connection. With answer
// false it never services the hub's requests, so its keepalives go unanswered
// while the TCP connection stays up — a registrant that has stopped responding,
// which is what a keepalive exists to notice.
func rawRegistrant(t *testing.T, h *testHub, id string, signer ssh.Signer, answer bool) ssh.Conn {
	t.Helper()
	nc, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatalf("dial the hub: %v", err)
	}
	conn, chans, reqs, err := ssh.NewClientConn(nc, h.addr, &ssh.ClientConfig{
		User:            id,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(h.key.PublicKey()),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("register %s: %v", id, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		for ch := range chans {
			_ = ch.Reject(ssh.Prohibited, "test registrant")
		}
	}()
	if answer {
		go ssh.DiscardRequests(reqs)
	}
	return conn
}

func TestHubOnChangeFiresOnAddAndRemove(t *testing.T) {
	a, b := sshtest.MustGenerateSigner(), sshtest.MustGenerateSigner()
	h, changes, _ := watchChanges(t, map[string]ssh.PublicKey{"proxy-b": b.PublicKey(), "proxy-a": a.PublicKey()}, nil)

	connB := rawRegistrant(t, h, "proxy-b", b, true)
	changes.want(t, "proxy-b registering", "proxy-b")
	connA := rawRegistrant(t, h, "proxy-a", a, true)
	changes.want(t, "proxy-a registering", "proxy-a", "proxy-b")

	_ = connB.Close()
	changes.want(t, "proxy-b's connection ending", "proxy-a")
	if !h.hub.Drop("proxy-a") {
		t.Fatal("Drop found no registration")
	}
	changes.want(t, "proxy-a dropped by the hub")
	_ = connA.Close()
	changes.none(t, "an already-dropped registration's connection ending")
}

func TestHubOnChangeFiresWhenAKeepaliveLapses(t *testing.T) {
	signer := sshtest.MustGenerateSigner()
	h, changes, _ := watchChanges(t, map[string]ssh.PublicKey{testDownstream: signer.PublicKey()}, func(o *HubOptions) {
		o.KeepaliveInterval = 20 * time.Millisecond
		o.KeepaliveTimeout = 100 * time.Millisecond
	})

	rawRegistrant(t, h, testDownstream, signer, false)
	changes.want(t, "registering", testDownstream)
	changes.want(t, "the keepalive lapsing")
	if h.hub.Registered(testDownstream) {
		t.Error("the unresponsive registration is still held")
	}
}

func TestHubOnChangeIgnoresASameIDReplacement(t *testing.T) {
	signer := sshtest.MustGenerateSigner()
	h, changes, _ := watchChanges(t, map[string]ssh.PublicKey{testDownstream: signer.PublicKey()}, nil)

	first := rawRegistrant(t, h, testDownstream, signer, true)
	changes.want(t, "registering", testDownstream)

	rawRegistrant(t, h, testDownstream, signer, true)
	// The hub closes the registration it replaced; once that has happened the
	// replacement is complete, and the set never stopped naming the id.
	closed := make(chan struct{})
	go func() {
		_ = first.Wait()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("the replaced registration was not closed")
	}
	changes.none(t, "a same-id replacement")
	if !h.hub.Registered(testDownstream) {
		t.Error("the replacement is not registered")
	}
}

// TestHubOnChangeFiresAtShutdown: shutdown empties the set, and every call on
// the way there is a real removal. How many calls that is depends on a race the
// hub does not order — each registration's keepalive loop drops itself when the
// context ends, while closeAll removes whatever is left — so the test asserts
// what holds either way: the set only shrinks, never more than once per id, and
// ends empty.
func TestHubOnChangeFiresAtShutdown(t *testing.T) {
	a, b := sshtest.MustGenerateSigner(), sshtest.MustGenerateSigner()
	h, changes, stop := watchChanges(t, map[string]ssh.PublicKey{"proxy-a": a.PublicKey(), "proxy-b": b.PublicKey()}, nil)
	rawRegistrant(t, h, "proxy-a", a, true)
	changes.want(t, "proxy-a registering", "proxy-a")
	rawRegistrant(t, h, "proxy-b", b, true)
	changes.want(t, "proxy-b registering", "proxy-a", "proxy-b")

	stop()
	prev := 2
	for calls := 1; ; calls++ {
		set := changes.next(t, "shutdown")
		if len(set) >= prev || calls > 2 {
			t.Fatalf("shutdown call %d saw %v after a set of %d; every call must be a removal", calls, set, prev)
		}
		if prev = len(set); prev == 0 {
			break
		}
	}
	changes.none(t, "the closed registrations' connections ending after shutdown")
}

func TestHubOnChangeIsOptional(t *testing.T) {
	signer := sshtest.MustGenerateSigner()
	h := startHub(t, map[string]ssh.PublicKey{testDownstream: signer.PublicKey()})
	conn := rawRegistrant(t, h, testDownstream, signer, true)
	waitFor(t, "the registration", func() bool { return h.hub.Registered(testDownstream) })
	_ = conn.Close()
	waitFor(t, "the deregistration", func() bool { return !h.hub.Registered(testDownstream) })
}

func TestHubRegistrationsAreSorted(t *testing.T) {
	ids := []string{"proxy-c", "proxy-a", "proxy-b"}
	signers := map[string]ssh.Signer{}
	authorized := map[string]ssh.PublicKey{}
	for _, id := range ids {
		signers[id] = sshtest.MustGenerateSigner()
		authorized[id] = signers[id].PublicKey()
	}
	h := startHub(t, authorized)
	for _, id := range ids {
		rawRegistrant(t, h, id, signers[id], true)
	}
	waitFor(t, "three registrations", func() bool { return len(h.hub.Registrations()) == 3 })
	for range 20 { // map order would show up within a few reads
		if got, want := h.hub.Registrations(), []string{"proxy-a", "proxy-b", "proxy-c"}; !slices.Equal(got, want) {
			t.Fatalf("Registrations() = %v, want %v", got, want)
		}
	}
}
