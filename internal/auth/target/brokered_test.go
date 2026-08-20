// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package target

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hoplock/proxy/internal/control"
	"github.com/hoplock/proxy/internal/sshtest"
)

// mapCredentialSource is a CredentialSource over material a test holds, and the
// shortest possible demonstration of the seam: a Hoplock Control that mints
// per-session credentials implements this same interface.
type mapCredentialSource struct {
	creds map[string]*Credential
	calls []CredentialRequest
}

func (s *mapCredentialSource) Name() string { return "map" }

func (s *mapCredentialSource) Credential(_ context.Context, req CredentialRequest) (*Credential, error) {
	s.calls = append(s.calls, req)
	cred, ok := s.creds[req.key()]
	if !ok {
		return nil, ErrNoCredential
	}
	return cred, nil
}

func brokeredRoute(params map[string]string) *control.TargetAuth {
	return &control.TargetAuth{Method: control.TargetAuthBrokeredKey, Params: params}
}

// newBrokeredCredential returns a credential and a distinctive slice of its
// material, for asserting that the material does not turn up anywhere.
func newBrokeredCredential(t *testing.T) (*Credential, []byte) {
	t.Helper()
	_, pem, err := sshtest.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	// The middle of the PEM: the base64 body, which is the part that is
	// actually secret and is long enough not to collide with anything.
	body := bytes.TrimSpace(pem)
	marker := body[len(body)/2 : len(body)/2+48]
	return &Credential{PrivateKey: pem}, append([]byte(nil), marker...)
}

// TestBrokeredKeyLeavesTheTargetUnmodified is the acceptance criterion for
// D6a: a session against a device the proxy cannot administer works, and the
// device is exactly as it was.
func TestBrokeredKeyLeavesTheTargetUnmodified(t *testing.T) {
	h := startFakeHost(t)
	ctx := context.Background()

	// An account that already exists, with a key file the proxy must not touch.
	const account = "netadmin"
	home := h.addAccount(t, account, time.Hour)
	keysPath := filepath.Join(home, ".ssh", "authorized_keys")
	keysBefore, err := os.ReadFile(keysPath)
	if err != nil {
		t.Fatalf("read authorized_keys: %v", err)
	}
	passwdBefore, err := os.ReadFile(h.passwd)
	if err != nil {
		t.Fatalf("read passwd: %v", err)
	}

	cred, _ := newBrokeredCredential(t)
	source := &mapCredentialSource{creds: map[string]*Credential{"core-switch": cred}}
	auth, err := NewBrokeredKeyAuthenticator(BrokeredKeyOptions{Source: source})
	if err != nil {
		t.Fatalf("NewBrokeredKeyAuthenticator: %v", err)
	}

	tgt := h.tgt()
	tgt.Auth = brokeredRoute(map[string]string{
		ParamUsername:      account,
		ParamCredentialRef: "core-switch",
	})
	access, err := auth.Provision(ctx, testIdentity(), tgt)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if got := access.ClientConfig.User; got != account {
		t.Errorf("login = %q, want the pre-existing account %q", got, account)
	}

	// The session works.
	loginAs(t, h, access.ClientConfig)

	// Nothing ran on the target — not a command, not a management login.
	if scripts := h.scripts(); len(scripts) != 0 {
		t.Errorf("brokered-key ran %d command(s) on the target: %v", len(scripts), scripts)
	}
	passwdAfter, err := os.ReadFile(h.passwd)
	if err != nil {
		t.Fatalf("read passwd: %v", err)
	}
	if !bytes.Equal(passwdBefore, passwdAfter) {
		t.Error("brokered-key modified the target's account database")
	}
	keysAfter, err := os.ReadFile(keysPath)
	if err != nil {
		t.Fatalf("read authorized_keys: %v", err)
	}
	if !bytes.Equal(keysBefore, keysAfter) {
		t.Error("brokered-key modified the account's authorized_keys")
	}

	if err := access.Close(ctx); err != nil {
		t.Errorf("teardown: %v", err)
	}
	if scripts := h.scripts(); len(scripts) != 0 {
		t.Errorf("brokered-key teardown ran %d command(s) on the target: %v", len(scripts), scripts)
	}
}

// TestBrokeredCredentialIsZeroed is the teardown guarantee for a method with no
// remote state: the only thing it holds is the credential, so the only thing it
// can destroy is the credential — and it must.
func TestBrokeredCredentialIsZeroed(t *testing.T) {
	h := startFakeHost(t)
	ctx := context.Background()

	for _, tc := range []struct {
		name string
		cred func(t *testing.T) (*Credential, []byte)
	}{
		{
			name: "a private key",
			cred: func(t *testing.T) (*Credential, []byte) {
				cred, _ := newBrokeredCredential(t)
				return cred, cred.PrivateKey
			},
		},
		{
			name: "a password",
			cred: func(*testing.T) (*Credential, []byte) {
				pw := []byte("appliance-console-password")
				return &Credential{Password: pw}, pw
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cred, material := tc.cred(t)
			source := &mapCredentialSource{creds: map[string]*Credential{"ref": cred}}
			auth, err := NewBrokeredKeyAuthenticator(BrokeredKeyOptions{Source: source, Username: "netadmin"})
			if err != nil {
				t.Fatalf("NewBrokeredKeyAuthenticator: %v", err)
			}

			tgt := h.tgt()
			tgt.Auth = brokeredRoute(map[string]string{ParamCredentialRef: "ref"})
			access, err := auth.Provision(ctx, testIdentity(), tgt)
			if err != nil {
				t.Fatalf("Provision: %v", err)
			}
			if err := access.Close(ctx); err != nil {
				t.Fatalf("teardown: %v", err)
			}
			if !allZero(material) {
				t.Errorf("credential material survived teardown: %q", material)
			}
			// Teardown runs on every exit path, so it runs more than once.
			if err := access.Close(ctx); err != nil {
				t.Errorf("second teardown = %v, want nil", err)
			}
		})
	}
}

// TestBrokeredCredentialNeverAppearsAnywhere is the disclosure criterion: the
// material is in memory for one session, and in nothing else.
func TestBrokeredCredentialNeverAppearsAnywhere(t *testing.T) {
	h := startFakeHost(t)
	ctx := context.Background()

	// The credential lives in a directory source, which is the only place on
	// disk it is allowed to be.
	store := t.TempDir()
	cred, marker := newBrokeredCredential(t)
	pem := append([]byte(nil), cred.PrivateKey...)
	credPath := filepath.Join(store, "core-switch.key")
	if err := os.WriteFile(credPath, pem, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	source, err := NewDirCredentialSource(store, "")
	if err != nil {
		t.Fatalf("NewDirCredentialSource: %v", err)
	}

	var logs bytes.Buffer
	auth, err := NewBrokeredKeyAuthenticator(BrokeredKeyOptions{
		Source:   source,
		Username: "netadmin",
		Logger:   log.New(&logs, "", 0),
	})
	if err != nil {
		t.Fatalf("NewBrokeredKeyAuthenticator: %v", err)
	}

	tgt := h.tgt()
	tgt.Auth = brokeredRoute(map[string]string{ParamCredentialRef: "core-switch"})
	access, err := auth.Provision(ctx, testIdentity(), tgt)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	loginAs(t, h, access.ClientConfig)
	if err := access.Close(ctx); err != nil {
		t.Fatalf("teardown: %v", err)
	}

	// Every failure mode's error string, too: an error is the likeliest place
	// for material to escape, because nobody reviews an error format string
	// the way they review a log line.
	var errText strings.Builder
	for _, ref := range []string{"core-switch", "missing", "../../etc/shadow"} {
		bad := h.tgt()
		bad.Auth = brokeredRoute(map[string]string{ParamCredentialRef: ref, "unknown": "1"})
		if _, err := auth.Provision(ctx, testIdentity(), bad); err != nil {
			errText.WriteString(err.Error())
		}
	}
	// A credential that is not a key at all: the parse error is x/crypto's.
	if err := os.WriteFile(filepath.Join(store, "broken.key"), []byte("not a key: "+string(marker)), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	broken := h.tgt()
	broken.Auth = brokeredRoute(map[string]string{ParamCredentialRef: "broken"})
	if _, err := auth.Provision(ctx, testIdentity(), broken); err != nil {
		errText.WriteString(err.Error())
	}

	if bytes.Contains(logs.Bytes(), marker) {
		t.Errorf("the credential appears in the log:\n%s", logs.String())
	}
	if strings.Contains(errText.String(), string(marker)) {
		t.Errorf("the credential appears in an error: %s", errText.String())
	}
	if logs.Len() == 0 {
		t.Error("the session logged nothing at all, so this test proves nothing")
	}

	// On disk: nothing anywhere under the temporary roots but the store's own
	// files, which is where the material was put deliberately.
	for _, root := range []string{h.root, store} {
		if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			if filepath.Dir(path) == store {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if bytes.Contains(data, marker) {
				t.Errorf("the credential was written to %s", path)
			}
			return nil
		}); err != nil {
			t.Fatalf("WalkDir: %v", err)
		}
	}
}

// TestBrokeredKeyRefusesAnUnknownParameter: the contract's rule holds for this
// method too — an unknown parameter may be a constraint.
func TestBrokeredKeyRefusesAnUnknownParameter(t *testing.T) {
	cred, _ := newBrokeredCredential(t)
	source := &mapCredentialSource{creds: map[string]*Credential{"ref": cred}}
	auth, err := NewBrokeredKeyAuthenticator(BrokeredKeyOptions{Source: source, Username: "netadmin"})
	if err != nil {
		t.Fatalf("NewBrokeredKeyAuthenticator: %v", err)
	}

	tgt := Target{Host: "switch.example.com", Port: 22}
	tgt.Auth = brokeredRoute(map[string]string{ParamCredentialRef: "ref", "rotate_after": "1h"})
	if _, err := auth.Provision(context.Background(), testIdentity(), tgt); !errors.Is(err, ErrUnknownParam) {
		t.Errorf("Provision = %v, want errors.Is(..., ErrUnknownParam)", err)
	}
	if len(source.calls) != 0 {
		t.Error("a refused route still fetched a credential")
	}
}

// TestBrokeredKeyWithoutMaterialIsAnOutage: the reference names nothing this
// proxy holds, which is an operator's problem and not a policy denial.
func TestBrokeredKeyWithoutMaterialIsAnOutage(t *testing.T) {
	source := &mapCredentialSource{creds: map[string]*Credential{}}
	auth, err := NewBrokeredKeyAuthenticator(BrokeredKeyOptions{Source: source, Username: "netadmin"})
	if err != nil {
		t.Fatalf("NewBrokeredKeyAuthenticator: %v", err)
	}
	tgt := Target{Host: "switch.example.com", Port: 22}
	tgt.Auth = brokeredRoute(map[string]string{ParamCredentialRef: "absent"})
	if _, err := auth.Provision(context.Background(), testIdentity(), tgt); !errors.Is(err, ErrNoCredential) {
		t.Errorf("Provision = %v, want errors.Is(..., ErrNoCredential)", err)
	}
}

// TestBrokeredKeyFallsBackToTheTargetAndLogin covers the route that names
// neither a reference nor a username: the source keys on the target, and the
// session logs in as the authenticated user.
func TestBrokeredKeyFallsBackToTheTargetAndLogin(t *testing.T) {
	cred, _ := newBrokeredCredential(t)
	source := &mapCredentialSource{creds: map[string]*Credential{"switch.example.com": cred}}
	auth, err := NewBrokeredKeyAuthenticator(BrokeredKeyOptions{Source: source})
	if err != nil {
		t.Fatalf("NewBrokeredKeyAuthenticator: %v", err)
	}

	tgt := Target{Host: "switch.example.com", Port: 22, Auth: brokeredRoute(nil)}
	access, err := auth.Provision(context.Background(), testIdentity(), tgt)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if got, want := access.ClientConfig.User, "alice"; got != want {
		t.Errorf("login = %q, want the authenticated login %q", got, want)
	}
	if got, want := source.calls[0].key(), "switch.example.com"; got != want {
		t.Errorf("credential keyed on %q, want %q", got, want)
	}
	if got, want := source.calls[0].Subject, testIdentity().Subject; got != want {
		t.Errorf("credential requested for subject %q, want %q", got, want)
	}
}

// TestDirCredentialSourceRefusesATraversingReference: the reference comes from
// the network, and it names a file.
func TestDirCredentialSourceRefusesATraversingReference(t *testing.T) {
	source, err := NewDirCredentialSource(t.TempDir(), "")
	if err != nil {
		t.Fatalf("NewDirCredentialSource: %v", err)
	}
	for _, ref := range []string{"../../etc/shadow", "sub/dir", "a/../../b", ""} {
		if _, err := source.Credential(context.Background(), CredentialRequest{Ref: ref}); !errors.Is(err, ErrInvalidParam) {
			t.Errorf("reference %q = %v, want errors.Is(..., ErrInvalidParam)", ref, err)
		}
	}
}

// TestEnvCredentialSource covers the source a container-scheduled proxy uses.
func TestEnvCredentialSource(t *testing.T) {
	source, err := NewEnvCredentialSource("HOPLOCK_BROKERED_")
	if err != nil {
		t.Fatalf("NewEnvCredentialSource: %v", err)
	}
	_, pem, err := sshtest.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	t.Setenv("HOPLOCK_BROKERED_CORE_SWITCH", string(pem))

	cred, err := source.Credential(context.Background(), CredentialRequest{Ref: "core-switch"})
	if err != nil {
		t.Fatalf("Credential: %v", err)
	}
	if !bytes.Equal(cred.PrivateKey, pem) {
		t.Error("the source returned different material than the environment held")
	}
	if _, err := source.Credential(context.Background(), CredentialRequest{Ref: "absent"}); !errors.Is(err, ErrNoCredential) {
		t.Errorf("an unset variable = %v, want errors.Is(..., ErrNoCredential)", err)
	}
}

// TestCredentialZeroIsSafeOnNothing keeps teardown callable in every state.
func TestCredentialZeroIsSafeOnNothing(t *testing.T) {
	var cred *Credential
	cred.Zero()
	empty := &Credential{}
	empty.Zero()
	if !reflect.DeepEqual(empty, &Credential{}) {
		t.Error("zeroing an empty credential changed it")
	}
}

// TestBrokeredKeyPasswordCredential covers the appliances that offer nothing
// better than a password.
func TestBrokeredKeyPasswordCredential(t *testing.T) {
	source := &mapCredentialSource{creds: map[string]*Credential{
		"ref": {Password: []byte("console")},
	}}
	auth, err := NewBrokeredKeyAuthenticator(BrokeredKeyOptions{Source: source, Username: "admin"})
	if err != nil {
		t.Fatalf("NewBrokeredKeyAuthenticator: %v", err)
	}
	tgt := Target{Host: "filer.example.com", Port: 22, Auth: brokeredRoute(map[string]string{ParamCredentialRef: "ref"})}
	access, err := auth.Provision(context.Background(), testIdentity(), tgt)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if len(access.ClientConfig.Auth) != 1 {
		t.Fatalf("client configuration has %d authentication methods, want 1", len(access.ClientConfig.Auth))
	}
	if err := access.Close(context.Background()); err != nil {
		t.Errorf("teardown: %v", err)
	}
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return len(b) > 0
}
