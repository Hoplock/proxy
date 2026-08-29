// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package sshtest

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

// A fake FortiOS device, in the spirit of Target above (PLAN §5.3, phase 0014).
//
// It speaks enough of the CLI to accept, reject, and enumerate administrators,
// and it can be told to fail in the ways real hardware fails. It exists because
// the alternative — testing a device driver by stubbing the strings it sends —
// asserts only that this repository sends the strings this repository sends,
// which is exactly the test that lets a driver ship broken. CI must never need
// an appliance, and with this it does not.
//
// Four behaviours here are faithful on purpose, because each one is a thing
// the driver has to survive:
//
//   - it ECHOES what it is given, as a device with a terminal does, so the
//     driver's echo stripping is exercised rather than assumed;
//   - it PAGES long output when asked to, because `config system console`
//     defaults to paging and that setting is permanent and device-wide;
//   - it reports failure as OUTPUT TEXT with no exit status, because that is
//     the only failure channel FortiOS has;
//   - it has a VDOM MODE, and in multi-VDOM mode it refuses `config system
//     admin` outside `config global`.
//
// That last one is phase 0015's lesson and it is worth stating plainly:
// docs/FORTIOS-DOC-VERIFICATION.md found that the driver's command sequence is
// wrong on a multi-VDOM unit, and THE TESTS PASSED THE WHOLE TIME — because
// this fake accepted every sequence the report faults. A fake more permissive
// than the device it stands in for converts a driver bug into a green build, so
// where the real device is known to be strict, so is this.
//
// Where the real behaviour is NOT known, this fake does not invent one. Each
// such place carries a comment naming the open question instead; searching for
// "unverified" finds them.

// FortiOSAccount is one administrator on the fake device.
type FortiOSAccount struct {
	Name      string
	Profile   string
	TrustHost string
	// IP6TrustHost is the IPv6 half of the source restriction. An account the
	// driver never wrote it on holds FortiOSOpenIPv6TrustHost, which is the
	// device's own default and means "reachable from any IPv6 address" — so a
	// test can assert the pin is real rather than half-applied.
	IP6TrustHost string
	// VDOM is the virtual domain a per-VDOM administrator is scoped to. Nothing
	// sets it yet; it is here so that a driver which starts sending `set vdom`
	// is asserted against rather than silently accepted.
	VDOM string
	// Password and PublicKey are what the driver installed. They are here so a
	// test can assert the credential ARRIVED; nothing in the device ever prints
	// them, exactly as a real one prints `ENC …` rather than the secret.
	Password  string
	PublicKey string
}

// FortiOSOpenIPv6TrustHost is `ip6-trusthost1`'s documented default: "Default
// allows access from any IPv6 address".
const FortiOSOpenIPv6TrustHost = "::/0"

// FortiOSFaults make the device fail the way real ones do.
type FortiOSFaults struct {
	// MaxNameLen overrides the administrator-name limit the device enforces.
	// Zero means FortiOSMaxNameLen.
	MaxNameLen int
	// RejectProfile makes `set accprofile` fail for any profile not in
	// Profiles, which is what a device does when policy names a profile the
	// customer never created.
	RejectProfile bool
	// FailCommand fails every command matching this pattern with FortiOS's
	// generic refusal. It is how a test reaches the config-mode error path.
	FailCommand *regexp.Regexp
	// PageEvery emits the pager's marker every n lines of `show` output. Zero
	// means no paging.
	PageEvery int
}

// FortiOSOptions configures a FakeFortiOS.
type FortiOSOptions struct {
	// HostKey is the device's host key. Generated when nil.
	HostKey ssh.Signer
	// Hostname is what the prompt is built from. Empty means "FGT-TEST".
	Hostname string
	// AdminUser and AdminPassword are the privileged login the proxy uses.
	// Empty means "hoplock-mgmt" and "mgmt-secret".
	AdminUser     string
	AdminPassword string
	// Accounts are administrators that already exist.
	Accounts []FortiOSAccount
	// Profiles are the access profiles the device has. Empty means the
	// documented built-ins (FortiOSBuiltinProfiles).
	Profiles []string
	// VDOMMode is what `get system status` reports as the unit's virtual
	// domain configuration. Empty means FortiOSVDOMDisabled.
	//
	// It is a MODE rather than a fault because it is not a malfunction: a
	// multi-VDOM FortiGate is a correctly configured unit, and on PLAN §13's
	// UC1 estate it is likely the common one. What makes it interesting is that
	// the administrator table moves inside `config global` there, so a driver
	// written against the single-VDOM recipe is silently editing the wrong
	// scope.
	VDOMMode string
	// Faults make it misbehave.
	Faults FortiOSFaults
}

// FortiOSMaxNameLen is the administrator-name length FortiOS accepts.
//
// 64, per `config system admin`'s `name` parameter ("string, Maximum length:
// 64") in every supported release. It was 35 here until phase 0015, which is
// the general figure the naming-rules KB gives for most name fields and the
// right one for `accprofile` and `schedule` — not for this one.
const FortiOSMaxNameLen = 64

// The virtual domain configurations `get system status` reports.
//
// Fortinet documents `disable` and `multiple` as the values of the "Virtual
// domain configuration" line, and the Administration Guide adds split-task
// mode as a third shape of the same feature. A driver that has not been written
// for virtual domains should decline every value but `disable`.
const (
	FortiOSVDOMDisabled  = "disable"
	FortiOSVDOMMultiple  = "multiple"
	FortiOSVDOMSplitTask = "split-task"
)

// FortiOSBuiltinProfiles are the access profiles Fortinet documents.
//
// THREE, not four. `prof_admin_readonly` appears in no Fortinet source and used
// to be in this list, which meant a driver defaulting to a profile that does
// not exist resolved happily against a fake that had invented it.
var FortiOSBuiltinProfiles = []string{"super_admin", "prof_admin", "super_admin_readonly"}

// FakeFortiOS is an in-process SSH server that answers FortiOS CLI commands.
type FakeFortiOS struct {
	listener net.Listener
	config   *ssh.ServerConfig
	hostKey  ssh.Signer
	hostname string
	profiles map[string]bool
	vdomMode string
	faults   FortiOSFaults

	wg     sync.WaitGroup
	closed chan struct{}

	adminUser     string
	adminPassword string

	mu       sync.Mutex
	accounts map[string]FortiOSAccount
	commands []string
	logins   []string
	down     bool
}

// StartFortiOS starts a fake device on a loopback port.
func StartFortiOS(opts FortiOSOptions) (*FakeFortiOS, error) {
	return StartFortiOSOn("127.0.0.1:0", opts)
}

// StartFortiOSOn starts a fake device on a given address, for the end-to-end
// topology, where it has to be reachable from another container.
func StartFortiOSOn(addr string, opts FortiOSOptions) (*FakeFortiOS, error) {
	hostKey := opts.HostKey
	if hostKey == nil {
		var err error
		if hostKey, err = GenerateSigner(); err != nil {
			return nil, err
		}
	}
	user, password := opts.AdminUser, opts.AdminPassword
	if user == "" {
		user = "hoplock-mgmt"
	}
	if password == "" {
		password = "mgmt-secret"
	}

	d := &FakeFortiOS{
		hostKey:  hostKey,
		hostname: opts.Hostname,
		profiles: map[string]bool{},
		faults:   opts.Faults,
		closed:   make(chan struct{}),
		accounts: map[string]FortiOSAccount{},
	}
	if d.hostname == "" {
		d.hostname = "FGT-TEST"
	}
	if d.faults.MaxNameLen == 0 {
		d.faults.MaxNameLen = FortiOSMaxNameLen
	}
	d.vdomMode = opts.VDOMMode
	if d.vdomMode == "" {
		d.vdomMode = FortiOSVDOMDisabled
	}
	profiles := opts.Profiles
	if len(profiles) == 0 {
		// The documented FortiOS built-ins, so a profile resolves against the
		// same set a real unit has — and, just as importantly, so one that is
		// not on a real unit fails here.
		profiles = append([]string(nil), FortiOSBuiltinProfiles...)
	}
	for _, p := range profiles {
		d.profiles[p] = true
	}
	for _, a := range opts.Accounts {
		if a.Profile == "" {
			a.Profile = "super_admin"
		}
		if a.IP6TrustHost == "" {
			a.IP6TrustHost = FortiOSOpenIPv6TrustHost
		}
		d.accounts[a.Name] = a
	}

	d.adminUser, d.adminPassword = user, password

	// The device accepts TWO kinds of login, and the second one is the whole
	// point: the privileged administrator the proxy manages it as, and any
	// administrator that exists in its own table with the credential that table
	// holds. A fake that only accepted the first would let a driver create an
	// account it could never log in as — which is exactly the gap that shipped
	// once, because every unit test asserted the account EXISTED and none
	// connected as it.
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, given []byte) (*ssh.Permissions, error) {
			d.record(func() { d.logins = append(d.logins, conn.User()) })
			if conn.User() == d.adminUser && string(given) == d.adminPassword {
				return nil, nil
			}
			if acct, ok := d.account(conn.User()); ok && acct.Password != "" && acct.Password == string(given) {
				return nil, nil
			}
			return nil, errors.New("sshtest: bad device login")
		},
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			d.record(func() { d.logins = append(d.logins, conn.User()) })
			acct, ok := d.account(conn.User())
			if !ok || acct.PublicKey == "" {
				return nil, errors.New("sshtest: bad device login")
			}
			want, _, _, _, err := ssh.ParseAuthorizedKey([]byte(acct.PublicKey))
			if err != nil || !bytes.Equal(want.Marshal(), key.Marshal()) {
				return nil, errors.New("sshtest: bad device login")
			}
			return nil, nil
		},
	}
	cfg.AddHostKey(hostKey)
	d.config = cfg

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("sshtest: listen: %w", err)
	}
	d.listener = ln

	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		d.serve()
	}()
	return d, nil
}

// Host, Port, HostKey and Addr mirror Target's accessors.
func (d *FakeFortiOS) Addr() net.Addr { return d.listener.Addr() }

func (d *FakeFortiOS) Host() string {
	host, _, _ := net.SplitHostPort(d.listener.Addr().String())
	return host
}

func (d *FakeFortiOS) Port() int {
	_, port, _ := net.SplitHostPort(d.listener.Addr().String())
	p := 0
	_, _ = fmt.Sscanf(port, "%d", &p)
	return p
}

func (d *FakeFortiOS) HostKey() ssh.PublicKey { return d.hostKey.PublicKey() }

// Accounts is the administrator table, for assertions.
func (d *FakeFortiOS) Accounts() map[string]FortiOSAccount {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make(map[string]FortiOSAccount, len(d.accounts))
	for k, v := range d.accounts {
		out[k] = v
	}
	return out
}

// Commands is every command line the device was sent, in order. It is what
// makes "no credential appears anywhere it should not" an assertion rather than
// a hope: a test can search this and the device's own output for the secret.
func (d *FakeFortiOS) Commands() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.commands...)
}

// Logins is every administrator name that attempted the management login.
func (d *FakeFortiOS) Logins() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.logins...)
}

// AddAccount puts an administrator on the device without going through the CLI,
// which is how a test stages what a crashed session left behind.
func (d *FakeFortiOS) AddAccount(a FortiOSAccount) {
	if a.IP6TrustHost == "" {
		a.IP6TrustHost = FortiOSOpenIPv6TrustHost
	}
	d.record(func() { d.accounts[a.Name] = a })
}

// SetUnreachable makes the device refuse and drop connections, standing in for
// one that has gone away mid-teardown.
func (d *FakeFortiOS) SetUnreachable(down bool) {
	d.record(func() { d.down = down })
}

func (d *FakeFortiOS) unreachable() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.down
}

// Close stops the device.
func (d *FakeFortiOS) Close() error {
	select {
	case <-d.closed:
	default:
		close(d.closed)
	}
	err := d.listener.Close()
	d.wg.Wait()
	return err
}

func (d *FakeFortiOS) serve() {
	for {
		conn, err := d.listener.Accept()
		if err != nil {
			return
		}
		if d.unreachable() {
			_ = conn.Close()
			continue
		}
		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			d.handleConn(conn)
		}()
	}
}

func (d *FakeFortiOS) handleConn(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	sshConn, chans, reqs, err := ssh.NewServerConn(conn, d.config)
	if err != nil {
		return
	}
	defer func() { _ = sshConn.Close() }()
	go ssh.DiscardRequests(reqs)

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(ssh.UnknownChannelType, "only sessions")
			continue
		}
		ch, in, err := newCh.Accept()
		if err != nil {
			return
		}
		go func() {
			for req := range in {
				// A device answers a shell request and ignores the rest; an
				// exec request is refused, which is why the driver asks for a
				// shell.
				if req.WantReply {
					_ = req.Reply(req.Type == "shell" || req.Type == "pty-req", nil)
				}
			}
		}()
		d.converse(ch)
	}
}

// sendDeviceExit reports the session's exit status.
//
// A shell channel that closes without one makes an OpenSSH client exit 255,
// which would make every device scenario look like a connection failure rather
// than a session that ran.
func sendDeviceExit(ch ssh.Channel, status uint32) {
	_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
}

// converse is the device's CLI. It is a small state machine over three modes,
// because that is what the real one is.
func (d *FakeFortiOS) converse(ch ssh.Channel) {
	defer func() {
		sendDeviceExit(ch, 0)
		_ = ch.Close()
	}()

	// The banner a FortiGate greets a login with. It is here so the driver's
	// "read past the banner to the first prompt" is exercised: a driver that
	// attributed this to its first command would misread every session.
	fmt.Fprintf(ch, "FortiGate-VM64 (%s)\r\nSystem is starting...\r\n", d.hostname)
	d.prompt(ch, "")

	// scope is the nesting the CLI is in. On a multi-VDOM unit the
	// administrator table lives one level deeper, inside `config global`, and
	// modelling that as a stack rather than a flag is what lets the fake tell
	// `config system admin` from `config global` / `config system admin`.
	var (
		scope   []string
		editing *FortiOSAccount
	)
	scanner := bufio.NewScanner(ch)
	scanner.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(strings.TrimRight(scanner.Text(), "\r"))
		if line == "" {
			d.prompt(ch, promptSuffix(scope, editing))
			continue
		}
		d.record(func() { d.commands = append(d.commands, line) })
		// The echo. A real device with a terminal sends the line back before
		// its answer.
		fmt.Fprintf(ch, "%s\r\n", line)

		if d.faults.FailCommand != nil && d.faults.FailCommand.MatchString(line) {
			d.fail(ch, failReturnCode)
			d.prompt(ch, promptSuffix(scope, editing))
			continue
		}

		done := d.dispatch(ch, line, &scope, &editing)
		if done {
			return
		}
		d.prompt(ch, promptSuffix(scope, editing))
	}
}

// failReturnCode is the generic refusal line FortiOS appends to a failure.
//
// -1 is on Fortinet's documented table of CLI error codes. This fake used -3,
// which is not on it — harmless, because the driver reports the code and never
// branches on it, but an invented example in the one place a reader would take
// one from.
const failReturnCode = "Command fail. Return code -1"

// dispatch runs one command and reports whether the session should end.
func (d *FakeFortiOS) dispatch(ch ssh.Channel, line string, scope *[]string, editing **FortiOSAccount) bool {
	fields := strings.Fields(line)
	inAdmin := len(*scope) > 0 && (*scope)[len(*scope)-1] == "admin"
	switch {
	case line == "exit" || line == "quit":
		return true

	case line == "get system status":
		d.showStatus(ch)
		return false

	case line == "config global":
		// `config global` exists only when virtual domains are enabled. On a
		// single-VDOM unit the real device has no such command; it is answered
		// here the way any unknown command is.
		if d.vdomMode == FortiOSVDOMDisabled {
			d.fail(ch, "Unknown action 0")
			d.fail(ch, failReturnCode)
			return false
		}
		*scope = append(*scope, "global")
		return false

	case line == "config system admin":
		// The strictness this fake exists for. On a multi-VDOM unit Fortinet's
		// own recipe reaches this table through `config global`, and a driver
		// that sends it at the top level is editing something else — or
		// nothing.
		//
		// UNVERIFIED: what a real multi-VDOM unit does with `config system
		// admin` at the top level is not documented — a parse error, or
		// something quieter. This fake refuses it, which is the strictest
		// reading and the one that fails a driver bug rather than hiding it. It
		// is on phase 0015's hardware list; do not read the exact wording below
		// as Fortinet's.
		if d.vdomMode != FortiOSVDOMDisabled && !containsScope(*scope, "global") {
			d.fail(ch, "Command parse error before 'system'")
			d.fail(ch, failReturnCode)
			return false
		}
		*scope = append(*scope, "admin")
		return false

	case line == "abort":
		// The property the driver relies on for failure isolation: an
		// uncommitted block is discarded outright.
		*editing = nil
		*scope = nil
		return false

	case line == "end":
		if *editing != nil {
			d.commit(**editing)
			*editing = nil
		}
		if len(*scope) > 0 {
			*scope = (*scope)[:len(*scope)-1]
		}
		return false

	case line == "next":
		if *editing != nil {
			d.commit(**editing)
			*editing = nil
		}
		return false

	case inAdmin && len(fields) >= 2 && fields[0] == "edit":
		name := unquote(strings.Join(fields[1:], " "))
		if len(name) > d.faults.MaxNameLen {
			// UNVERIFIED WORDING: Fortinet documents that a failure carries a
			// `Command fail. Return code -X` line, which is what the driver
			// actually matches, but publishes no canonical text for a
			// too-long name. The first line here is plausible rather than
			// quoted, and nothing may be made to depend on it.
			d.fail(ch, fmt.Sprintf("The string is too long. The maximum allowed length is %d.", d.faults.MaxNameLen))
			d.fail(ch, failReturnCode)
			return false
		}
		existing, ok := d.account(name)
		if !ok {
			// A fresh entry starts at the device's own defaults, which for the
			// IPv6 restriction means WIDE OPEN.
			existing = FortiOSAccount{Name: name, IP6TrustHost: FortiOSOpenIPv6TrustHost}
		}
		*editing = &existing
		return false

	case inAdmin && len(fields) >= 2 && fields[0] == "delete":
		name := unquote(strings.Join(fields[1:], " "))
		if _, ok := d.account(name); !ok {
			d.fail(ch, "Entry not found in datasource")
			d.fail(ch, failReturnCode)
			return false
		}
		d.record(func() { delete(d.accounts, name) })
		return false

	case *editing != nil && len(fields) >= 3 && fields[0] == "set":
		d.set(ch, fields, *editing)
		return false

	case strings.HasPrefix(line, "show system admin"):
		d.showAdmins(ch)
		return false

	default:
		d.fail(ch, "Unknown action 0")
		d.fail(ch, failReturnCode)
		return false
	}
}

// containsScope reports whether a nesting level is open.
func containsScope(scope []string, want string) bool {
	for _, s := range scope {
		if s == want {
			return true
		}
	}
	return false
}

// showStatus answers `get system status`.
//
// Only the line a driver has any business reading is modelled. Fortinet
// documents it as the way to tell whether virtual domains are enabled — "the
// output will display the 'Virtual domain configuration' status" — with
// `disable` and `multiple` as its values.
func (d *FakeFortiOS) showStatus(ch ssh.Channel) {
	fmt.Fprintf(ch, "Version: FortiGate-VM64 v7.6.6,build2775,250000 (GA.F)\r\n")
	fmt.Fprintf(ch, "Hostname: %s\r\n", d.hostname)
	fmt.Fprintf(ch, "Virtual domains status: 1 in NAT mode, 0 in TP mode\r\n")
	fmt.Fprintf(ch, "Virtual domain configuration: %s\r\n", d.vdomMode)
}

// set applies one field to the entry being edited.
func (d *FakeFortiOS) set(ch ssh.Channel, fields []string, acct *FortiOSAccount) {
	value := unquote(strings.Join(fields[2:], " "))
	switch fields[1] {
	case "accprofile":
		if d.faults.RejectProfile && !d.profiles[value] {
			d.fail(ch, "entry not found in datasource")
			d.fail(ch, fmt.Sprintf("value parse error before '%s'", value))
			d.fail(ch, failReturnCode)
			return
		}
		acct.Profile = value
	case "trusthost1":
		// An `ipv4-classnet` field: an address and a netmask, and nothing else.
		// Modelling the type is the point — phase 0014 rendered an IPv6 source
		// as `<addr>/128` and wrote it here, and a fake that stored any string
		// let that pass.
		if !ipv4ClassnetPattern.MatchString(value) {
			d.fail(ch, fmt.Sprintf("value parse error before '%s'", value))
			d.fail(ch, failReturnCode)
			return
		}
		acct.TrustHost = value
	case "ip6-trusthost1":
		// The parallel IPv6 restriction, defaulting to `::/0` on a real unit —
		// which is why an account pinned only through `trusthost1` is not
		// pinned. The fake starts every account at the documented default so a
		// test can tell "closed" from "never set".
		if !ipv6PrefixPattern.MatchString(value) {
			d.fail(ch, fmt.Sprintf("value parse error before '%s'", value))
			d.fail(ch, failReturnCode)
			return
		}
		acct.IP6TrustHost = value
	case "password":
		acct.Password = value
	case "ssh-public-key1":
		acct.PublicKey = value
	case "vdom":
		acct.VDOM = value
	default:
		d.fail(ch, "Unknown action 0")
		d.fail(ch, failReturnCode)
	}
}

// ipv4ClassnetPattern is the `<address> <netmask>` pair `trusthost1` takes.
var ipv4ClassnetPattern = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3} (\d{1,3}\.){3}\d{1,3}$`)

// ipv6PrefixPattern is the `<address>/<length>` form `ip6-trusthost1` takes.
// It is deliberately loose about the address: what it is here to reject is an
// IPv4 pair or a bare address, not a malformed hextet.
var ipv6PrefixPattern = regexp.MustCompile(`^[0-9A-Fa-f:]+/\d{1,3}$`)

// showAdmins renders the administrator table the way `show system admin` does,
// paging it when the fault says to.
func (d *FakeFortiOS) showAdmins(ch ssh.Channel) {
	d.mu.Lock()
	names := make([]string, 0, len(d.accounts))
	for name := range d.accounts {
		names = append(names, name)
	}
	sort.Strings(names)
	accounts := make([]FortiOSAccount, 0, len(names))
	for _, name := range names {
		accounts = append(accounts, d.accounts[name])
	}
	d.mu.Unlock()

	lines := []string{"config system admin"}
	for _, a := range accounts {
		lines = append(lines, fmt.Sprintf("    edit %q", a.Name))
		if a.Profile != "" {
			lines = append(lines, fmt.Sprintf("        set accprofile %q", a.Profile))
		}
		if a.TrustHost != "" {
			lines = append(lines, fmt.Sprintf("        set trusthost1 %s", a.TrustHost))
		}
		if a.IP6TrustHost != "" && a.IP6TrustHost != FortiOSOpenIPv6TrustHost {
			lines = append(lines, fmt.Sprintf("        set ip6-trusthost1 %s", a.IP6TrustHost))
		}
		if a.VDOM != "" {
			lines = append(lines, fmt.Sprintf("        set vdom %q", a.VDOM))
		}
		// A real device prints the credential as an opaque blob, never the
		// secret. So does this one — a fake that leaked it would make the
		// "nothing secret is ever printed" assertions vacuous.
		if a.Password != "" {
			lines = append(lines, `        set password ENC xxxxxxxxxxxxxxxx`)
		}
		if a.PublicKey != "" {
			lines = append(lines, fmt.Sprintf("        set ssh-public-key1 %q", a.PublicKey))
		}
		lines = append(lines, "    next")
	}
	lines = append(lines, "end")

	for i, l := range lines {
		fmt.Fprintf(ch, "%s\r\n", l)
		if d.faults.PageEvery > 0 && (i+1)%d.faults.PageEvery == 0 && i+1 < len(lines) {
			// The pager waits for a keypress. Anything the driver sends is
			// consumed by the scanner in converse as a blank line, which is
			// exactly how a real pager behaves towards a space.
			fmt.Fprint(ch, "--More--")
			buf := make([]byte, 1)
			if _, err := ch.Read(buf); err != nil {
				return
			}
			fmt.Fprint(ch, "\r        \r")
		}
	}
}

func (d *FakeFortiOS) commit(a FortiOSAccount) {
	d.record(func() { d.accounts[a.Name] = a })
}

func (d *FakeFortiOS) account(name string) (FortiOSAccount, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	a, ok := d.accounts[name]
	return a, ok
}

func (d *FakeFortiOS) fail(ch ssh.Channel, message string) {
	fmt.Fprintf(ch, "%s\r\n", message)
}

func (d *FakeFortiOS) prompt(ch ssh.Channel, suffix string) {
	if suffix != "" {
		fmt.Fprintf(ch, "%s (%s) # ", d.hostname, suffix)
		return
	}
	fmt.Fprintf(ch, "%s # ", d.hostname)
}

func (d *FakeFortiOS) record(f func()) {
	d.mu.Lock()
	defer d.mu.Unlock()
	f()
}

func promptSuffix(scope []string, editing *FortiOSAccount) string {
	if editing != nil {
		return editing.Name
	}
	if len(scope) == 0 {
		return ""
	}
	return scope[len(scope)-1]
}

// unquote strips the quoting the driver applies, so the device stores the value
// the driver meant rather than the one it wrote.
func unquote(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 && strings.HasPrefix(v, `"`) && strings.HasSuffix(v, `"`) {
		v = v[1 : len(v)-1]
		v = strings.ReplaceAll(v, `\"`, `"`)
		v = strings.ReplaceAll(v, `\\`, `\`)
	}
	return v
}
