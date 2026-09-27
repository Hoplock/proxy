// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package sshtest

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
)

// KexInitTarget speaks just enough SSH to send ONE key-exchange-init message —
// its own name-lists, advertised verbatim — and to record the one the client
// sends (phase 0045). It never completes a key exchange.
//
// It exists for two things no in-process target built on x/crypto can do.
// First, advertise algorithms the library cannot negotiate: sntrup761 is
// OpenSSH's hybrid and not x/crypto's, and a floor defined by what THIS proxy
// implements has to be shown refusing a target that offers only that. Second,
// show what the proxy actually puts on the wire: the client's KEXINIT is the
// offer itself, after every default the library fills in, which is the level
// "offers exactly this" is honestly asserted at.
//
// A client that finds nothing in common fails exactly as it would against a
// real target, with the library's typed negotiation error; one that does find
// something is disconnected before any key exchange.
type KexInitTarget struct {
	listener net.Listener
	opts     KexInitOptions

	mu     sync.Mutex
	client []KexInit
	wg     sync.WaitGroup
}

// KexInitOptions are the name-lists the target advertises. An empty list is
// sent empty, which no client can agree with; the defaults below are what a
// test sets when it does not care about an axis.
type KexInitOptions struct {
	KeyExchanges []string
	HostKeys     []string
	Ciphers      []string
	MACs         []string
}

// KexInit is one side's advertised name-lists, as they crossed the wire.
type KexInit struct {
	KeyExchanges        []string
	HostKeys            []string
	CiphersClientServer []string
	CiphersServerClient []string
	MACsClientServer    []string
	MACsServerClient    []string
}

// KexInitDefaults fills every axis a test left empty with something any
// client of this repository can agree with, so only the axis under test fails.
func KexInitDefaults(opts KexInitOptions) KexInitOptions {
	if len(opts.KeyExchanges) == 0 {
		opts.KeyExchanges = []string{"curve25519-sha256"}
	}
	if len(opts.HostKeys) == 0 {
		opts.HostKeys = []string{"ssh-ed25519"}
	}
	if len(opts.Ciphers) == 0 {
		opts.Ciphers = []string{"aes128-gcm@openssh.com", "aes128-ctr"}
	}
	if len(opts.MACs) == 0 {
		opts.MACs = []string{"hmac-sha2-256-etm@openssh.com", "hmac-sha2-256"}
	}
	return opts
}

// StartKexInitTarget listens on a loopback port.
func StartKexInitTarget(opts KexInitOptions) (*KexInitTarget, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("sshtest: listen: %w", err)
	}
	t := &KexInitTarget{listener: l, opts: opts}
	t.wg.Add(1)
	go t.serve()
	return t, nil
}

// Host is the address to dial.
func (t *KexInitTarget) Host() string {
	host, _, _ := net.SplitHostPort(t.listener.Addr().String())
	return host
}

// Port is the port to dial.
func (t *KexInitTarget) Port() int {
	_, port, _ := net.SplitHostPort(t.listener.Addr().String())
	n, _ := strconv.Atoi(port)
	return n
}

// Addr is "host:port".
func (t *KexInitTarget) Addr() string { return t.listener.Addr().String() }

// ClientKexInits returns every KEXINIT a client has sent, oldest first.
func (t *KexInitTarget) ClientKexInits() []KexInit {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]KexInit(nil), t.client...)
}

// Close stops the listener and waits for every connection to finish.
func (t *KexInitTarget) Close() error {
	err := t.listener.Close()
	t.wg.Wait()
	return err
}

func (t *KexInitTarget) serve() {
	defer t.wg.Done()
	for {
		conn, err := t.listener.Accept()
		if err != nil {
			return
		}
		t.wg.Add(1)
		go func() {
			defer t.wg.Done()
			defer func() { _ = conn.Close() }()
			// Hang up as soon as the client's KEXINIT is recorded. Ours was
			// written first, so a client that finds nothing in common has it
			// and fails on the negotiation; one that finds something fails on
			// the missing key exchange instead of waiting for it.
			if init, err := t.exchange(conn); err == nil {
				t.mu.Lock()
				t.client = append(t.client, init)
				t.mu.Unlock()
			}
		}()
	}
}

// exchange trades identification strings and KEXINIT messages.
func (t *KexInitTarget) exchange(conn net.Conn) (KexInit, error) {
	if _, err := io.WriteString(conn, "SSH-2.0-Hoplock_KexInit_Test\r\n"); err != nil {
		return KexInit{}, err
	}
	r := bufio.NewReader(conn)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return KexInit{}, err
		}
		if strings.HasPrefix(line, "SSH-") {
			break
		}
	}
	if _, err := conn.Write(t.packet()); err != nil {
		return KexInit{}, err
	}
	payload, err := readPacket(r)
	if err != nil {
		return KexInit{}, err
	}
	return parseKexInit(payload)
}

// msgKexInit is SSH_MSG_KEXINIT (RFC 4253 §7.1).
const msgKexInit = 20

// packet is this target's KEXINIT as an unencrypted binary packet (RFC 4253
// §6): no MAC is negotiated yet, so a packet is its length, its padding length,
// the payload, and at least four bytes of padding to a multiple of eight.
func (t *KexInitTarget) packet() []byte {
	o := t.opts
	payload := []byte{msgKexInit}
	cookie := make([]byte, 16)
	_, _ = rand.Read(cookie)
	payload = append(payload, cookie...)
	for _, list := range [][]string{
		o.KeyExchanges, o.HostKeys, o.Ciphers, o.Ciphers, o.MACs, o.MACs,
		{"none"}, {"none"}, nil, nil,
	} {
		joined := strings.Join(list, ",")
		payload = binary.BigEndian.AppendUint32(payload, uint32(len(joined)))
		payload = append(payload, joined...)
	}
	payload = append(payload, 0)                        // first_kex_packet_follows
	payload = binary.BigEndian.AppendUint32(payload, 0) // reserved

	padding := 8 - (5+len(payload))%8
	if padding < 4 {
		padding += 8
	}
	packet := binary.BigEndian.AppendUint32(nil, uint32(1+len(payload)+padding))
	packet = append(packet, byte(padding))
	packet = append(packet, payload...)
	return append(packet, make([]byte, padding)...)
}

func readPacket(r io.Reader) ([]byte, error) {
	var head [5]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(head[:4])
	padding := uint32(head[4])
	if length < padding+1 || length > 256*1024 {
		return nil, errors.New("sshtest: malformed packet")
	}
	body := make([]byte, length-1)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return body[:length-1-padding], nil
}

func parseKexInit(payload []byte) (KexInit, error) {
	if len(payload) < 17 || payload[0] != msgKexInit {
		return KexInit{}, errors.New("sshtest: the first packet was not a KEXINIT")
	}
	rest := payload[17:]
	var lists [6][]string
	for i := range lists {
		if len(rest) < 4 {
			return KexInit{}, errors.New("sshtest: truncated KEXINIT")
		}
		n := binary.BigEndian.Uint32(rest[:4])
		if uint32(len(rest)-4) < n {
			return KexInit{}, errors.New("sshtest: truncated KEXINIT")
		}
		if n > 0 {
			lists[i] = strings.Split(string(rest[4:4+n]), ",")
		}
		rest = rest[4+n:]
	}
	return KexInit{
		KeyExchanges:        lists[0],
		HostKeys:            lists[1],
		CiphersClientServer: lists[2],
		CiphersServerClient: lists[3],
		MACsClientServer:    lists[4],
		MACsServerClient:    lists[5],
	}, nil
}
