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
	"strconv"
	"strings"
	"sync"
	"time"

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
//   - it has a VDOM MODE, and in one it refuses `config system admin`,
//     `show system admin` and `show system vdom` outside `config global`, and
//     refuses `set vdom` naming a virtual domain it does not have.
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
	// VDOM is the virtual domain a per-VDOM administrator is scoped to, set by
	// `set vdom` (phase 0016). Empty means the administrator is global, which
	// on a partitioned unit is the wider of the two scopes — so a test asserts
	// on this field rather than on the account merely existing.
	VDOM string
	// Schedule is the one-time schedule this administrator's login is bounded
	// by, set by `set schedule` (phase 0017). Empty means "no schedule means no
	// restrictions", which is the device's own wording for the default.
	Schedule string
	// Password and PublicKey are what the driver installed. They are here so a
	// test can assert the credential ARRIVED; nothing in the device ever prints
	// them, exactly as a real one prints `ENC …` rather than the secret.
	Password  string
	PublicKey string
}

// FortiOSOpenIPv6TrustHost is `ip6-trusthost1`'s documented default: "Default
// allows access from any IPv6 address".
const FortiOSOpenIPv6TrustHost = "::/0"

// FortiOSSchedule is one `config firewall schedule onetime` entry.
//
// It is modelled because it is the object a device-enforced expiry actually IS
// on this platform: `set schedule` on an administrator is a reference, and a
// reference to nothing is what a driver that got the second object wrong
// produces. A fake that stored `set schedule` as a string on the account — and
// nothing else — would accept a driver that never created the schedule, which
// is precisely the session whose audit record claims a deadline the device does
// not hold.
type FortiOSSchedule struct {
	Name string
	// Start and End are the device's own `hh:mm yyyy/mm/dd` renderings, kept as
	// the strings the driver sent so a test can assert on what was WRITTEN
	// rather than on what this fake managed to parse back.
	Start string
	End   string
	// ExpirationDays is "write an event log message this many days before the
	// schedule expires", documented with a minimum of 0, a maximum of 100 and a
	// DEFAULT OF 3 — which is why a new entry here starts at
	// FortiOSDefaultExpirationDays rather than at zero. Every schedule this
	// proxy creates is shorter than three days, so a driver that leaves the
	// field alone earns the unit a warning log per session, and a fake that
	// started it at zero would hide that.
	ExpirationDays int
}

// FortiOSDefaultExpirationDays is `expiration-days`' documented default.
const FortiOSDefaultExpirationDays = 3

// FortiOSScheduleTimeLayout is the `hh:mm yyyy/mm/dd` format of a one-time
// schedule's start and end.
const FortiOSScheduleTimeLayout = "15:04 2006/01/02"

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
	// HideClock makes the unit refuse to say what time it is, by every route:
	// `execute date`, `execute time`, and the `System time` line in
	// `get system status`.
	//
	// It is a FAULT rather than a mode because a driver that renders an
	// absolute expiry datetime from the WRONG clock writes a window that is
	// hours out — in one direction an account that cannot log in, in the other
	// an account the device honours past its deadline. What the fault is here
	// to prove is that the driver refuses instead.
	HideClock bool
	// NoExecuteClock hides only `execute date` and `execute time`, leaving the
	// status line, so the fallback path can be exercised on its own. A unit
	// that answers one and not the other is a unit whose clock is known, and
	// refusing it would be refusing a route over a command name.
	NoExecuteClock bool
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
	// VDOMs are the virtual domains the unit has. It is read only when
	// VDOMMode is a VDOM mode, and empty means the documented defaults for that
	// mode: `root` alone under `multiple`, and the fixed management/traffic
	// pair under `split-task`.
	//
	// They are modelled because `set vdom` naming one the unit does not have is
	// how a route with a stale VDOM name fails, and a fake that accepted any
	// string would turn that into a silent success — the same class of hole as
	// accepting `config system admin` at the top level, which is what this fake
	// exists to have closed.
	VDOMs []string
	// Schedules are one-time schedules that already exist, which is how a test
	// stages the object a crashed session left behind.
	Schedules []FortiOSSchedule
	// Now is the device's own clock. Nil means time.Now.
	//
	// It is settable because the device's clock is not the proxy's, and that
	// difference is the whole reason the driver reads a time off `get system
	// status` at all: a fake that could only be "now" would let a driver
	// computing the window from its own clock pass every test and then write an
	// eight-hour-wrong window on a unit in another timezone.
	Now func() time.Time
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
// domain configuration" line, and the Administration Guide adds split-task mode
// as a third shape of the same feature — one this fake serves like `multiple`,
// because its own "Create per-VDOM administrators" procedure is the same recipe.
// A value that is none of the three is what a driver has to decline.
const (
	FortiOSVDOMDisabled  = "disable"
	FortiOSVDOMMultiple  = "multiple"
	FortiOSVDOMSplitTask = "split-task"
)

// FortiOSDefaultVDOM is the management virtual domain every partitioned unit
// has, and FortiOSTrafficVDOM is the second one split-task mode fixes beside
// it — "the management VDOM (root) and the traffic VDOM (FG-traffic)".
const (
	FortiOSDefaultVDOM = "root"
	FortiOSTrafficVDOM = "FG-traffic"
)

// The one-time schedule table's command lines, spelled once.
const (
	scheduleTableLine = "config firewall schedule onetime"
	scheduleShowLine  = "show firewall schedule onetime"
)

// FortiOSMaxScheduleNameLen is the schedule-name limit this device enforces.
//
// 31 — `config firewall schedule onetime`'s own `name` parameter ("Onetime
// schedule name. | string | Maximum length: 31"), identical across the
// supported releases. It was 32 here, from the naming KB's general figure for
// "Schedule names", and 35 was never in the running: 35 is the width of the
// fields that REFERENCE a schedule (`system admin`'s `schedule`,
// `firewall policy`'s `schedule`), so a name can be referenced that cannot
// exist.
const FortiOSMaxScheduleNameLen = 31

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
	vdoms    []string
	faults   FortiOSFaults

	wg     sync.WaitGroup
	closed chan struct{}

	adminUser     string
	adminPassword string

	mu        sync.Mutex
	now       func() time.Time
	accounts  map[string]FortiOSAccount
	schedules map[string]FortiOSSchedule
	commands  []string
	logins    []string
	down      bool
	// strandedSessions counts CLI sessions that ended while still inside a
	// configuration block. On a real unit that is what holds an object lock
	// under workspace mode, and it is the failure a driver whose unwinding does
	// not follow the nesting produces — silently, because every command it sent
	// succeeded.
	strandedSessions int
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
		hostKey:   hostKey,
		hostname:  opts.Hostname,
		profiles:  map[string]bool{},
		faults:    opts.Faults,
		closed:    make(chan struct{}),
		accounts:  map[string]FortiOSAccount{},
		schedules: map[string]FortiOSSchedule{},
		now:       opts.Now,
	}
	if d.now == nil {
		d.now = time.Now
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
	d.vdoms = append([]string(nil), opts.VDOMs...)
	if len(d.vdoms) == 0 {
		switch d.vdomMode {
		case FortiOSVDOMMultiple:
			d.vdoms = []string{FortiOSDefaultVDOM}
		case FortiOSVDOMSplitTask:
			d.vdoms = []string{FortiOSDefaultVDOM, FortiOSTrafficVDOM}
		}
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
	for _, sched := range opts.Schedules {
		d.schedules[sched.Name] = sched
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
				if !d.scheduleAllows(acct) {
					return nil, errors.New("sshtest: out_of_schedule")
				}
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
			if !d.scheduleAllows(acct) {
				return nil, errors.New("sshtest: out_of_schedule")
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

// Schedules is the one-time schedule table, for assertions. It is what makes
// "teardown removed BOTH objects" an assertion rather than a hope.
func (d *FakeFortiOS) Schedules() map[string]FortiOSSchedule {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make(map[string]FortiOSSchedule, len(d.schedules))
	for k, v := range d.schedules {
		out[k] = v
	}
	return out
}

// AddSchedule puts a one-time schedule on the device without going through the
// CLI, which is how a test stages the object a crashed session left behind
// before its administrator ever existed.
func (d *FakeFortiOS) AddSchedule(sched FortiOSSchedule) {
	d.record(func() { d.schedules[sched.Name] = sched })
}

// Now is the device's own clock, and SetNow moves it.
//
// Moving it is how a test closes a window without touching the account: what
// `set schedule` buys is that the DEVICE stops honouring the credential when
// the time passes, and a test that proved it by editing the account would be
// proving something else.
func (d *FakeFortiOS) Now() time.Time { return d.clock()() }

func (d *FakeFortiOS) SetNow(now func() time.Time) {
	d.record(func() { d.now = now })
}

// clock returns the device's clock under the lock, so that a test moving it
// races nothing. The function it returns is called OUTSIDE the lock, because a
// test's clock is a test's to write and this device must not hold a mutex
// through it.
func (d *FakeFortiOS) clock() func() time.Time {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.now
}

// scheduleAllows reports whether an administrator's schedule lets it log in
// now, which is what `set schedule` BUYS and therefore the only thing worth
// modelling about it.
//
// It is applied to BOTH authentication callbacks. Fortinet's field description
// is about the administrator — "Firewall schedule used to restrict when the
// administrator can log in" — and the denial their KB shows is at
// authentication; but the KB's worked example is a password login, and nothing
// read for phase 0017 says in so many words that a public-key login is checked
// the same way. UNVERIFIED, and on that phase's hardware list as the item the
// declaration rests on. It is modelled as covering both because that is the
// strictest reading and the one that fails a driver bug rather than hiding it —
// the same standard this fake applies to `config system admin` at the top level
// of a partitioned unit.
//
// A schedule the device does not have DENIES, rather than being ignored: a
// dangling reference is the shape a half-torn-down session leaves, and reading
// it as "no restrictions" would make the most dangerous outcome the quiet one.
func (d *FakeFortiOS) scheduleAllows(acct FortiOSAccount) bool {
	if acct.Schedule == "" {
		return true
	}
	d.mu.Lock()
	sched, ok := d.schedules[acct.Schedule]
	d.mu.Unlock()
	if !ok {
		return false
	}
	start, errStart := time.Parse(FortiOSScheduleTimeLayout, sched.Start)
	end, errEnd := time.Parse(FortiOSScheduleTimeLayout, sched.End)
	if errStart != nil || errEnd != nil {
		return false
	}
	now := d.clock()()
	wall := time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute(), now.Second(), 0, time.UTC)
	return !wall.Before(start) && wall.Before(end)
}

// Commands is every command line the device was sent, in order. It is what
// makes "no credential appears anywhere it should not" an assertion rather than
// a hope: a test can search this and the device's own output for the secret.
func (d *FakeFortiOS) Commands() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.commands...)
}

// StrandedSessions is how many CLI sessions ended inside a configuration
// block, which is what a driver whose unwinding does not follow the nesting
// leaves behind.
func (d *FakeFortiOS) StrandedSessions() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.strandedSessions
}

// VDOMs is the unit's virtual domains, for assertions.
func (d *FakeFortiOS) VDOMs() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.vdoms...)
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

	// The CLI's own state. `scope` is the nesting: on a multi-VDOM unit the
	// administrator table lives one level deeper, inside `config global`, and
	// modelling that as a stack rather than a flag is what lets the fake tell
	// `config system admin` from `config global` / `config system admin`.
	var st cliState
	// A session that ends inside a configuration block is recorded rather than
	// tidied up. The whole point of modelling it is that the driver's teardown
	// has to unwind its own nesting: a fake that quietly closed the block for
	// it would make an under-unwinding driver look correct.
	defer func() {
		if len(st.scope) > 0 {
			d.record(func() { d.strandedSessions++ })
		}
	}()
	scanner := bufio.NewScanner(ch)
	scanner.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(strings.TrimRight(scanner.Text(), "\r"))
		if line == "" {
			d.prompt(ch, st.promptSuffix())
			continue
		}
		d.record(func() { d.commands = append(d.commands, line) })
		// The echo. A real device with a terminal sends the line back before
		// its answer.
		fmt.Fprintf(ch, "%s\r\n", line)

		if d.faults.FailCommand != nil && d.faults.FailCommand.MatchString(line) {
			d.fail(ch, failReturnCode)
			d.prompt(ch, st.promptSuffix())
			continue
		}

		if done := d.dispatch(ch, line, &st); done {
			return
		}
		d.prompt(ch, st.promptSuffix())
	}
}

// failReturnCode is the generic refusal line FortiOS appends to a failure.
//
// -1 is on Fortinet's documented table of CLI error codes. This fake used -3,
// which is not on it — harmless, because the driver reports the code and never
// branches on it, but an invented example in the one place a reader would take
// one from.
const failReturnCode = "Command fail. Return code -1"

// cliState is where in the CLI one session currently is.
//
// It is a struct rather than a handful of out-parameters because phase 0017
// added a SECOND configuration table to this device — `config firewall schedule
// onetime` beside `config system admin` — and "which table is open, and which
// entry inside it" stopped being expressible as one pointer.
type cliState struct {
	// scope is the open nesting, innermost last: "global", "admin",
	// "schedule".
	scope []string
	// admin and sched are the entry being edited in whichever table is open.
	// At most one is ever set, because `edit` is only accepted inside a table.
	admin *FortiOSAccount
	sched *FortiOSSchedule
}

// in reports whether a table is the innermost open scope.
func (st *cliState) in(table string) bool {
	return len(st.scope) > 0 && st.scope[len(st.scope)-1] == table
}

func (st *cliState) promptSuffix() string {
	switch {
	case st.admin != nil:
		return st.admin.Name
	case st.sched != nil:
		return st.sched.Name
	case len(st.scope) == 0:
		return ""
	default:
		return st.scope[len(st.scope)-1]
	}
}

// dispatch runs one command and reports whether the session should end.
func (d *FakeFortiOS) dispatch(ch ssh.Channel, line string, st *cliState) bool {
	fields := strings.Fields(line)
	scope := &st.scope
	editing := &st.admin
	inAdmin := st.in("admin")
	inSchedule := st.in("schedule")
	switch {
	case line == "exit" || line == "quit":
		return true

	case line == "get system status":
		d.showStatus(ch)
		return false

	case line == "execute date" || line == "execute time":
		if d.faults.HideClock || d.faults.NoExecuteClock {
			d.fail(ch, "Unknown action 0")
			d.fail(ch, failReturnCode)
			return false
		}
		d.showClock(ch, line)
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
		st.admin, st.sched = nil, nil
		*scope = nil
		return false

	case line == "end":
		d.commitOpenEntry(st)
		if len(*scope) > 0 {
			*scope = (*scope)[:len(*scope)-1]
		}
		return false

	case line == "next":
		d.commitOpenEntry(st)
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

	case line == scheduleTableLine:
		// The one-time schedule table, and it is held to the SAME scope rule as
		// the administrator table: on a partitioned unit it is reached through
		// `config global`.
		//
		// UNVERIFIED, and it is the assumption phase 0017 most wants a real
		// unit to settle: firewall objects are ordinarily per-VDOM, and what
		// makes this one plausibly global is that a global administrator's
		// `set schedule` has to resolve against something it can see. The fake
		// takes the driver's reading so the two agree; a real unit that
		// disagrees fails the driver's `set schedule`, which is why the driver
		// creates the schedule BEFORE it references it.
		if d.vdomMode != FortiOSVDOMDisabled && !containsScope(*scope, "global") {
			d.fail(ch, "Command parse error before 'firewall'")
			d.fail(ch, failReturnCode)
			return false
		}
		*scope = append(*scope, "schedule")
		return false

	case inSchedule && len(fields) >= 2 && fields[0] == "edit":
		name := unquote(strings.Join(fields[1:], " "))
		if len(name) > FortiOSMaxScheduleNameLen {
			d.fail(ch, fmt.Sprintf("The string is too long. The maximum allowed length is %d.", FortiOSMaxScheduleNameLen))
			d.fail(ch, failReturnCode)
			return false
		}
		existing, ok := d.schedule(name)
		if !ok {
			existing = FortiOSSchedule{Name: name, ExpirationDays: FortiOSDefaultExpirationDays}
		}
		st.sched = &existing
		return false

	case inSchedule && len(fields) >= 2 && fields[0] == "delete":
		name := unquote(strings.Join(fields[1:], " "))
		if _, ok := d.schedule(name); !ok {
			d.fail(ch, "Entry not found in datasource")
			d.fail(ch, failReturnCode)
			return false
		}
		if user, ok := d.scheduleUser(name); ok {
			// UNVERIFIED, and the strictest reading: FortiOS refuses to delete
			// an object something still references, and `object is in use` is
			// the string it uses — cli.go already matches it. Whether it
			// applies to a schedule an administrator names is on phase 0017's
			// hardware list. It is modelled because it makes the TEARDOWN ORDER
			// load-bearing: a driver that deleted the schedule before the
			// administrator would pass against a permissive fake and leave
			// half the objects behind on a unit that behaves this way.
			// Fortinet's published wording for a still-referenced delete is
			// "The entry is used by other N entries" — a FortiSwitch KB, not a
			// page about schedules, so the WORDING is sourced and this
			// object's behaviour is still inferred. The count is 1 because
			// exactly one administrator can be found referencing it here.
			_ = user
			d.fail(ch, "The entry is used by other 1 entries.")
			d.fail(ch, failReturnCode)
			return false
		}
		d.record(func() { delete(d.schedules, name) })
		return false

	case st.sched != nil && len(fields) >= 3 && fields[0] == "set":
		d.setSchedule(ch, fields, st.sched)
		return false

	case strings.HasPrefix(line, scheduleShowLine):
		// A read of the same table, under the same scope rule.
		if d.vdomMode != FortiOSVDOMDisabled && !containsScope(*scope, "global") {
			d.fail(ch, "Command parse error before 'firewall'")
			d.fail(ch, failReturnCode)
			return false
		}
		d.showSchedules(ch)
		return false

	case strings.HasPrefix(line, "show system admin"):
		// The administrator table is a GLOBAL table. On a partitioned unit it
		// is read where it is configured — inside `config global` — and a
		// driver reading it at the top level is reading whatever the current
		// VDOM has, which is the enumerate-path half of the same gap phase 0015
		// found on the create path. An orphan sweep that reads the wrong table
		// finds nothing and reports success.
		if d.vdomMode != FortiOSVDOMDisabled && !containsScope(*scope, "global") {
			d.fail(ch, "Command parse error before 'system'")
			d.fail(ch, failReturnCode)
			return false
		}
		d.showAdmins(ch)
		return false

	case strings.HasPrefix(line, "show system vdom"):
		// `config system vdom` exists only on a unit that has virtual domains,
		// and it is a global table like the administrator one.
		if d.vdomMode == FortiOSVDOMDisabled {
			d.fail(ch, "Unknown action 0")
			d.fail(ch, failReturnCode)
			return false
		}
		if !containsScope(*scope, "global") {
			d.fail(ch, "Command parse error before 'system'")
			d.fail(ch, failReturnCode)
			return false
		}
		d.showVDOMs(ch)
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
	if !d.faults.HideClock {
		// The unit's own clock, in the shape `date` prints. It is here because
		// `set end` is an ABSOLUTE datetime in the device's local time, so a
		// driver that renders one has to ask the device what time it is —
		// and a fake that never answered would let a driver use its own clock
		// and pass.
		fmt.Fprintf(ch, "System time: %s\r\n", d.clock()().Format("Mon Jan 2 15:04:05 2006"))
	}
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
	case "schedule":
		// A reference, checked like every other reference on this platform. A
		// fake that stored the string without looking would accept a driver
		// that never created the schedule at all — an administrator with a
		// dangling deadline, on a session whose audit record says the device
		// holds one.
		if _, ok := d.schedule(value); !ok {
			d.fail(ch, "entry not found in datasource")
			d.fail(ch, fmt.Sprintf("value parse error before '%s'", value))
			d.fail(ch, failReturnCode)
			return
		}
		acct.Schedule = value
	case "vdom":
		// A VDOM that does not exist is refused the way any dangling reference
		// is on this platform. `Entry not found in datasource` is the string
		// FortiOS uses for exactly that, and the driver already reads it.
		if !d.hasVDOM(value) {
			d.fail(ch, "entry not found in datasource")
			d.fail(ch, fmt.Sprintf("value parse error before '%s'", value))
			d.fail(ch, failReturnCode)
			return
		}
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
		if a.Schedule != "" {
			lines = append(lines, fmt.Sprintf("        set schedule %q", a.Schedule))
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

// showVDOMs renders `config system vdom` the way `show` does — one `edit` per
// virtual domain, in the same shape as the administrator table, which is what
// lets a driver read both with one line matcher.
func (d *FakeFortiOS) showVDOMs(ch ssh.Channel) {
	vdoms := d.VDOMs()
	sort.Strings(vdoms)
	fmt.Fprint(ch, "config system vdom\r\n")
	for _, name := range vdoms {
		fmt.Fprintf(ch, "    edit %q\r\n", name)
		fmt.Fprint(ch, "    next\r\n")
	}
	fmt.Fprint(ch, "end\r\n")
}

func (d *FakeFortiOS) hasVDOM(name string) bool {
	for _, v := range d.VDOMs() {
		if v == name {
			return true
		}
	}
	return false
}

// setSchedule applies one field to the schedule entry being edited.
func (d *FakeFortiOS) setSchedule(ch ssh.Channel, fields []string, sched *FortiOSSchedule) {
	value := unquote(strings.Join(fields[2:], " "))
	switch fields[1] {
	case "start", "end":
		// The type is modelled, for trustHost1's reason: `hh:mm yyyy/mm/dd` is
		// a shape, and a driver that rendered a datetime some other way — or in
		// some other timezone's idea of one — must fail here rather than have
		// the fake store whatever it was handed.
		if _, err := time.Parse(FortiOSScheduleTimeLayout, value); err != nil {
			d.fail(ch, fmt.Sprintf("value parse error before '%s'", value))
			d.fail(ch, failReturnCode)
			return
		}
		if fields[1] == "start" {
			sched.Start = value
			return
		}
		sched.End = value
	case "expiration-days":
		days, err := strconv.Atoi(value)
		if err != nil || days < 0 || days > 100 {
			// The documented range is 0..100. Modelling it is what makes a
			// driver that writes something else fail here.
			d.fail(ch, fmt.Sprintf("value parse error before '%s'", value))
			d.fail(ch, failReturnCode)
			return
		}
		sched.ExpirationDays = days
	default:
		d.fail(ch, "Unknown action 0")
		d.fail(ch, failReturnCode)
	}
}

// showSchedules renders `show firewall schedule onetime` in the same shape as
// every other `show` on this device, which is what lets one line matcher read
// all of them.
func (d *FakeFortiOS) showSchedules(ch ssh.Channel) {
	schedules := d.Schedules()
	names := make([]string, 0, len(schedules))
	for name := range schedules {
		names = append(names, name)
	}
	sort.Strings(names)

	fmt.Fprintf(ch, "%s\r\n", scheduleTableLine)
	for _, name := range names {
		sched := schedules[name]
		fmt.Fprintf(ch, "    edit %q\r\n", name)
		if sched.Start != "" {
			fmt.Fprintf(ch, "        set start %s\r\n", sched.Start)
		}
		if sched.End != "" {
			fmt.Fprintf(ch, "        set end %s\r\n", sched.End)
		}
		if sched.ExpirationDays != FortiOSDefaultExpirationDays {
			fmt.Fprintf(ch, "        set expiration-days %d\r\n", sched.ExpirationDays)
		}
		fmt.Fprint(ch, "    next\r\n")
	}
	fmt.Fprint(ch, "end\r\n")
}

// commitOpenEntry commits whichever table's entry is open, which is what `next`
// does and what `end` does on its way out of the block.
// showClock answers the two documented clock commands.
//
// They are modelled because `set end` is an absolute datetime in the unit's
// LOCAL time, so a driver that used its own clock would write a window wrong by
// the offset between them — and a fake whose clock always agreed with the test
// process would let that pass. The Administration Guide prints both outputs
// verbatim, and this matches them.
func (d *FakeFortiOS) showClock(ch ssh.Channel, line string) {
	now := d.clock()()
	if line == "execute date" {
		fmt.Fprintf(ch, "current date is: %s\r\n", now.Format("2006-01-02"))
		return
	}
	fmt.Fprintf(ch, "current time is: %s\r\n", now.Format("15:04:05"))
	// The second line is real and is a TRAP: it is the time of the last NTP
	// SYNCHRONISATION, not the time now. A driver that read the clock off it
	// would put its window wherever that sync happened to be, so this fake
	// reports one that is deliberately hours stale.
	fmt.Fprintf(ch, "last ntp sync:%s\r\n", now.Add(-7*time.Hour).Format("Mon Jan 2 15:04:05 2006"))
}

func (d *FakeFortiOS) commitOpenEntry(st *cliState) {
	if st.admin != nil {
		d.commit(*st.admin)
		st.admin = nil
	}
	if st.sched != nil {
		sched := *st.sched
		d.record(func() { d.schedules[sched.Name] = sched })
		st.sched = nil
	}
}

func (d *FakeFortiOS) schedule(name string) (FortiOSSchedule, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	sched, ok := d.schedules[name]
	return sched, ok
}

// scheduleUser reports the administrator that references a schedule, if any.
func (d *FakeFortiOS) scheduleUser(name string) (string, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, a := range d.accounts {
		if a.Schedule == name {
			return a.Name, true
		}
	}
	return "", false
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
