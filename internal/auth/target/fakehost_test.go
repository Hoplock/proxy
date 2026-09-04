// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package target

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hoplock/proxy/internal/sshtest"
)

// fakeHost is a POSIX target the provisioning scripts really run on.
//
// It is not a mock of the scripts: /bin/sh parses and executes them exactly as
// a target's shell would, against a temporary root with its own account
// database. Only the four commands a test machine cannot honestly provide —
// useradd, userdel, id, getent — plus pkill and chown are replaced, and each
// replacement behaves like the real one down to its exit statuses ("user
// exists" is 9, "no such user" is 6), because those statuses are what the
// scripts branch on.
//
// A test that stubbed AdminSession.Run instead would assert that this package
// sends the strings it sends. That proves nothing about whether an account is
// actually created, whether teardown actually removes it, or whether a quoting
// mistake turns a provisioning script into something else — which are the only
// questions worth asking about code that runs as root on a customer's fleet.
type fakeHost struct {
	root   string
	bin    string
	home   string
	passwd string
	log    string
	mounts string
	rules4 string
	rules6 string
	target *sshtest.Target

	mu       sync.Mutex
	env      map[string]string
	commands []string
}

// startFakeHost builds the temporary root, writes the fake commands, and puts
// an SSH front end on it.
func startFakeHost(t *testing.T) *fakeHost {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the provisioning scripts are POSIX shell")
	}
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skipf("no /bin/sh: %v", err)
	}

	root, err := os.MkdirTemp("", "hoplock-fakehost-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })

	h := &fakeHost{
		root:   root,
		bin:    filepath.Join(root, "bin"),
		home:   filepath.Join(root, "home"),
		passwd: filepath.Join(root, "passwd"),
		log:    filepath.Join(root, "commands.log"),
		mounts: filepath.Join(root, "mounts"),
		rules4: filepath.Join(root, "rules4"),
		rules6: filepath.Join(root, "rules6"),
		env:    map[string]string{},
	}
	for _, dir := range []string{h.bin, h.home} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
	}
	if err := os.WriteFile(h.passwd, []byte("root:x:0:0::/root:/bin/sh\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	for name, body := range fakeCommands {
		path := filepath.Join(h.bin, name)
		if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
			t.Fatalf("WriteFile %s: %v", name, err)
		}
	}

	target, err := sshtest.StartTarget(sshtest.Options{Exec: h.exec})
	if err != nil {
		t.Fatalf("StartTarget: %v", err)
	}
	t.Cleanup(func() { _ = target.Close() })
	h.target = target
	return h
}

// exec runs one provisioning script under /bin/sh with the fake commands ahead
// of the real ones on PATH.
func (h *fakeHost) exec(command string) (stdout, stderr []byte, status uint32) {
	h.mu.Lock()
	h.commands = append(h.commands, command)
	env := []string{
		"PATH=" + h.bin + ":/usr/bin:/bin:/usr/sbin:/sbin",
		"FAKEHOST_PASSWD=" + h.passwd,
		"FAKEHOST_HOME=" + h.home,
		"FAKEHOST_LOG=" + h.log,
		"FAKEHOST_MOUNTS=" + h.mounts,
		"FAKEHOST_RULES4=" + h.rules4,
		"FAKEHOST_RULES6=" + h.rules6,
	}
	for k, v := range h.env {
		env = append(env, k+"="+v)
	}
	h.mu.Unlock()

	cmd := exec.Command("/bin/sh", "-c", command)
	cmd.Env = env
	var out, errOut strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	var exitErr *exec.ExitError
	switch err := cmd.Run(); {
	case err == nil:
	case errors.As(err, &exitErr):
		status = uint32(exitErr.ExitCode())
	default:
		status = 255
		errOut.WriteString(err.Error())
	}
	return []byte(out.String()), []byte(errOut.String()), status
}

// setEnv adds an environment variable to every script run after it — the knobs
// the fake commands use to fail on purpose.
func (h *fakeHost) setEnv(name, value string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.env[name] = value
}

// scripts are the scripts the host has been asked to run.
func (h *fakeHost) scripts() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.commands...)
}

// accounts are the account names in the fake passwd database.
func (h *fakeHost) accounts(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(h.passwd)
	if err != nil {
		t.Fatalf("read passwd: %v", err)
	}
	var names []string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		names = append(names, strings.SplitN(line, ":", 2)[0])
	}
	return names
}

// hasAccount reports whether the fake passwd database holds a name.
func (h *fakeHost) hasAccount(t *testing.T, name string) bool {
	t.Helper()
	for _, got := range h.accounts(t) {
		if got == name {
			return true
		}
	}
	return false
}

// ephemeralAccounts are the accounts created by the ephemeral method, whatever
// proxy they belong to.
func (h *fakeHost) ephemeralAccounts(t *testing.T) []string {
	t.Helper()
	var names []string
	for _, name := range h.accounts(t) {
		if strings.HasPrefix(name, principalPrefix) {
			names = append(names, name)
		}
	}
	return names
}

// addAccount writes an account straight into the fake host, standing in for one
// a previous process — or a different proxy — left behind.
func (h *fakeHost) addAccount(t *testing.T, name string, age time.Duration) string {
	t.Helper()
	home := filepath.Join(h.home, name)
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), []byte("ssh-ed25519 AAAA\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	data, err := os.ReadFile(h.passwd)
	if err != nil {
		t.Fatalf("read passwd: %v", err)
	}
	line := fmt.Sprintf("%s:x:1001:1001::%s:/bin/sh\n", name, home)
	if err := os.WriteFile(h.passwd, append(data, line...), 0o644); err != nil {
		t.Fatalf("write passwd: %v", err)
	}
	h.backdate(t, home, age)
	return home
}

// backdate ages a home directory, which is how a test says "this account was
// left behind a while ago". The reaper reads exactly this timestamp.
func (h *fakeHost) backdate(t *testing.T, home string, age time.Duration) {
	t.Helper()
	when := time.Now().Add(-age)
	if err := os.Chtimes(home, when, when); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}
}

// homeFor is where the fake host keeps an account's home directory.
func (h *fakeHost) homeFor(name string) string { return filepath.Join(h.home, name) }

// run executes one command on the fake host, for a test that needs to change
// the host BEHIND the proxy's back — the crash case, where something other than
// this process removed an account and left a rung's state behind.
func (h *fakeHost) run(t *testing.T, command string) ([]byte, error) {
	t.Helper()
	stdout, stderr, status := h.exec(command)
	if status != 0 {
		return stdout, fmt.Errorf("%q: exit %d: %s", command, status, stderr)
	}
	return stdout, nil
}

// breakCommand replaces one of the fake commands with one that always fails,
// which is how a test says "this target cannot do that".
//
// It REPLACES rather than removes, deliberately. Deleting the fake would expose
// whatever the machine running the tests happens to have on its own PATH — and
// a probe that then really installed a packet filter rule would be a unit test
// editing the firewall of whoever ran it.
func (h *fakeHost) breakCommand(t *testing.T, name string) {
	t.Helper()
	body := "#!/bin/sh\necho \"" + name + " $* (broken)\" >> \"$FAKEHOST_LOG\"\nexit 1\n"
	if err := os.WriteFile(filepath.Join(h.bin, name), []byte(body), 0o755); err != nil {
		t.Fatalf("break the fake %s: %v", name, err)
	}
}

// rules are the packet-filter rules the host currently holds, per family.
func (h *fakeHost) rules(t *testing.T, v6 bool) []string {
	t.Helper()
	path := h.rules4
	if v6 {
		path = h.rules6
	}
	return h.lines(t, path)
}

// mountPoints are the mount points the host currently holds.
func (h *fakeHost) mountPoints(t *testing.T) []string {
	t.Helper()
	var points []string
	for _, line := range h.lines(t, h.mounts) {
		fields := strings.Fields(line)
		for i := 0; i < len(fields)-1; i++ {
			if fields[i] == "on" {
				points = append(points, fields[i+1])
				break
			}
		}
	}
	return points
}

// commandLog is every command the fake host's replacements have run, in order.
// It is what a test asserts teardown ORDERING against: a rule removed after its
// account is a rule attached to whoever gets that uid next.
func (h *fakeHost) commandLog(t *testing.T) []string {
	t.Helper()
	return h.lines(t, h.log)
}

func (h *fakeHost) lines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var lines []string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// shellFor is the login shell the fake passwd database holds for an account.
func (h *fakeHost) shellFor(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(h.passwd)
	if err != nil {
		t.Fatalf("read passwd: %v", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) >= 7 && fields[0] == name {
			return fields[6]
		}
	}
	return ""
}

// authorizedKeys reads an account's authorized_keys file.
func (h *fakeHost) authorizedKeys(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(h.homeFor(name), ".ssh", "authorized_keys"))
	if err != nil {
		t.Fatalf("read authorized_keys: %v", err)
	}
	return string(data)
}

// tgt is the fake host as a route would name it, with its host key trusted.
func (h *fakeHost) tgt() Target {
	return Target{
		Host:            h.target.Host(),
		Port:            h.target.Port(),
		HostKeyCallback: ssh.FixedHostKey(h.target.HostKey()),
	}
}

// dialer is a management connection to the fake host. It is the production
// dialer: the SSH leg under a provisioning run is real.
func (h *fakeHost) dialer(t *testing.T) AdminDialer {
	t.Helper()
	dialer, err := NewSSHAdminDialer(SSHAdminOptions{
		Signer:  sshtest.MustGenerateSigner(),
		User:    "hoplock-admin",
		Timeout: 20 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewSSHAdminDialer: %v", err)
	}
	return dialer
}

// fakeCommands are the account-database commands a test machine cannot provide
// honestly. Everything else in the provisioning scripts — sh, printf, mkdir,
// chmod, rm, stat, date, cat — is the real thing.
var fakeCommands = map[string]string{
	"id": `#!/bin/sh
echo "id $*" >> "$FAKEHOST_LOG"
name=""
for a in "$@"; do case "$a" in -u) ;; *) name=$a ;; esac; done
grep -q "^$name:" "$FAKEHOST_PASSWD" || exit 1
awk -F: -v n="$name" '$1==n {print $3}' "$FAKEHOST_PASSWD"
exit 0
`,
	"useradd": `#!/bin/sh
echo "useradd $*" >> "$FAKEHOST_LOG"
home=""; shell=""; name=""
while [ $# -gt 0 ]; do
  case "$1" in
    -m) ;;
    -d) home=$2; shift ;;
    -s) shell=$2; shift ;;
    *) name=$1 ;;
  esac
  shift
done
[ -n "$name" ] || { echo "useradd: missing account name" >&2; exit 2; }
if grep -q "^$name:" "$FAKEHOST_PASSWD"; then
  echo "useradd: user '$name' already exists" >&2
  exit 9
fi
if [ -n "$FAKEHOST_USERADD_FAILS" ]; then
  echo "useradd: cannot create home directory (simulated)" >&2
  exit 12
fi
[ -n "$home" ] || home="$FAKEHOST_HOME/$name"
mkdir -p "$home" || exit 12
echo "$name:x:1001:1001::$home:$shell" >> "$FAKEHOST_PASSWD"
if [ -n "$FAKEHOST_FAILS_AFTER_USERADD" ]; then
  echo "useradd: failed after creating the account (simulated)" >&2
  exit 1
fi
exit 0
`,
	"userdel": `#!/bin/sh
echo "userdel $*" >> "$FAKEHOST_LOG"
remove=0; name=""
for a in "$@"; do case "$a" in -r) remove=1 ;; *) name=$a ;; esac; done
grep -q "^$name:" "$FAKEHOST_PASSWD" || { echo "userdel: user '$name' does not exist" >&2; exit 6; }
if [ -n "$FAKEHOST_USERDEL_FAILS" ]; then
  echo "userdel: cannot remove account (simulated)" >&2
  exit 8
fi
home=$(awk -F: -v n="$name" '$1==n {print $6}' "$FAKEHOST_PASSWD")
{ grep -v "^$name:" "$FAKEHOST_PASSWD" > "$FAKEHOST_PASSWD.tmp" || true; }
mv "$FAKEHOST_PASSWD.tmp" "$FAKEHOST_PASSWD"
if [ "$remove" = 1 ] && [ -n "$home" ]; then rm -rf "$home"; fi
exit 0
`,
	"getent": `#!/bin/sh
echo "getent $*" >> "$FAKEHOST_LOG"
[ "$1" = passwd ] || exit 2
cat "$FAKEHOST_PASSWD"
`,
	"pkill": `#!/bin/sh
echo "pkill $*" >> "$FAKEHOST_LOG"
exit 1
`,
	"chown": `#!/bin/sh
echo "chown $*" >> "$FAKEHOST_LOG"
exit 0
`,
	// The six commands phase 0019's enforcement rungs reach for. Each one is a
	// working model rather than a stub: the mounts file, the two rule files and
	// the passwd shell field are all really changed, so a test can ask whether
	// teardown removed a rule rather than whether this package sent a string
	// that looks like a removal.
	"usermod": `#!/bin/sh
echo "usermod $*" >> "$FAKEHOST_LOG"
shell=""; name=""
while [ $# -gt 0 ]; do case "$1" in -s) shell=$2; shift ;; *) name=$1 ;; esac; shift; done
grep -q "^$name:" "$FAKEHOST_PASSWD" || exit 6
awk -F: -v OFS=: -v n="$name" -v s="$shell" '$1==n {$7=s} {print}' "$FAKEHOST_PASSWD" > "$FAKEHOST_PASSWD.tmp"
mv "$FAKEHOST_PASSWD.tmp" "$FAKEHOST_PASSWD"
exit 0
`,
	"mount": `#!/bin/sh
echo "mount $*" >> "$FAKEHOST_LOG"
f=$FAKEHOST_MOUNTS
[ -f "$f" ] || : > "$f"
if [ "$#" -eq 0 ]; then cat "$f"; exit 0; fi
[ -z "$FAKEHOST_MOUNT_FAILS" ] || { echo "mount: operation not permitted (simulated)" >&2; exit 32; }
bind=0; opts=""; args=""
while [ $# -gt 0 ]; do
  case "$1" in
    --bind) bind=1 ;;
    -o) opts=$2; shift ;;
    *) args="$args $1" ;;
  esac
  shift
done
# shellcheck disable=SC2086
set -- $args
if [ "$bind" = 1 ]; then
  printf 'hoplock-bind on %s type none (rw)\n' "$2" >> "$f"
  exit 0
fi
case "$opts" in
  *remount*)
    grep -q " on $1 type" "$f" || { echo "mount: $1 is not mounted" >&2; exit 32; }
    awk -v t="$1" -v o="$opts" 'index($0, " on " t " type") { print "hoplock-bind on " t " type none (" o ")"; next } { print }' "$f" > "$f.tmp"
    mv "$f.tmp" "$f"
    exit 0 ;;
esac
exit 0
`,
	"umount": `#!/bin/sh
echo "umount $*" >> "$FAKEHOST_LOG"
f=$FAKEHOST_MOUNTS
[ -f "$f" ] || : > "$f"
t=""
for a in "$@"; do case "$a" in -*) ;; *) t=$a ;; esac; done
grep -q " on $t type" "$f" || exit 1
awk -v t="$t" '!index($0, " on " t " type")' "$f" > "$f.tmp"
mv "$f.tmp" "$f"
exit 0
`,
	"iptables":  fakeNetfilter("FAKEHOST_RULES4"),
	"ip6tables": fakeNetfilter("FAKEHOST_RULES6"),
	"setpriv": `#!/bin/sh
echo "setpriv $*" >> "$FAKEHOST_LOG"
while [ $# -gt 0 ]; do
  case "$1" in
    --no-new-privs) ;;
    --) shift; break ;;
    *) break ;;
  esac
  shift
done
[ "$#" -gt 0 ] || exit 1
exec "$@"
`,
	"sshd": `#!/bin/sh
echo "sshd $*" >> "$FAKEHOST_LOG"
case "${1-}" in
  -V) echo "${FAKEHOST_SSHD_VERSION:-OpenSSH_9.2p1 Debian-2+deb12u2, OpenSSL 3.0.11}" >&2; exit 0 ;;
  -T) echo "pubkeyauthentication ${FAKEHOST_SSHD_PUBKEY:-yes}"; exit 0 ;;
esac
exit 0
`,
}

// fakeNetfilter is a working iptables over a text file: append, delete by line
// number or by rule, list with line numbers, and dump.
//
// It exists because the uid hazard PLAN §6.5 records — a rule that outlives its
// account attaches to whoever gets that uid next — is only testable against
// something that really holds rules and really removes them. The fake useradd
// hands out the same uid every time, which makes the reuse case the DEFAULT
// here rather than something a test has to contrive.
func fakeNetfilter(file string) string {
	return `#!/bin/sh
echo "` + file + ` $*" >> "$FAKEHOST_LOG"
f=$` + file + `
[ -f "$f" ] || : > "$f"
case "${1-}" in
  -A) shift; chain=$1; shift; printf '%s\n' "-A $chain $*" >> "$f"; exit 0 ;;
  -D)
    [ -z "$FAKEHOST_RULE_DELETE_FAILS" ] || exit 0
    shift; chain=$1; shift
    if [ "$#" -eq 1 ] && [ "$1" -eq "$1" ] 2>/dev/null; then
      awk -v n="$1" 'NR != n' "$f" > "$f.tmp"
    else
      awk -v r="-A $chain $*" '$0 != r' "$f" > "$f.tmp"
    fi
    mv "$f.tmp" "$f"
    exit 0 ;;
  -L)
    i=0
    while IFS= read -r l; do i=$((i + 1)); printf '%s %s\n' "$i" "$l"; done < "$f"
    exit 0 ;;
  -S) cat "$f"; exit 0 ;;
esac
exit 0
`
}
