// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

// Command fake-device serves the in-process fake FortiOS appliance
// (internal/sshtest) on a real port, so the end-to-end topology has a device
// for the ephemeral-account method to provision on (D13, PLAN §5.3, §9).
//
// It is a TEST FIXTURE, in the same sense cmd/mock-control is: it exists so the
// topology can be a whole system rather than a system with a hole where the
// appliances are. It never ships to a customer, it holds nothing worth
// stealing, and every credential it knows arrives on its command line.
//
// The alternative was to leave phase 0014 proven by unit tests alone. The
// obligation in docs/PROTOCOL.md exists precisely because a change nobody has
// watched a real SSH client survive is a change with a hole in it, and "the
// devices are physical" would have been a reason to leave that hole open
// forever — the whole product is about gear you cannot put in CI.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/hoplock/proxy/internal/sshtest"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "fake-device: %v\n", err)
		os.Exit(1)
	}
}

// dumpAccounts prints the device's administrator table as the debug endpoint
// serves it.
func dumpAccounts(addr string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	url := addr
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "http://" + url
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url+"/debug/accounts", nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET /debug/accounts: %s", resp.Status)
	}
	if _, err := io.Copy(os.Stdout, resp.Body); err != nil {
		return err
	}
	return nil
}

// serveAccounts publishes one unit's administrator table.
//
// The same shape cmd/mock-control's /debug endpoints have, and for the same
// reason: a real appliance's administrator table is read over its own CLI, and
// a scenario that had to drive a CLI to check whether the proxy cleaned up
// would be asserting on the thing it is testing. The accounts live in this
// process's memory, so there is no file to read instead.
//
// `accounts` is the flat list of names the scenario suite has always read.
// `administrators` carries what a name cannot say — the access profile, and the
// virtual domain a VDOM-scoped administrator was created in — which on a
// partitioned unit is the whole scope of the account.
func serveAccounts(addr string, dev *sshtest.FakeFortiOS) (*http.Server, error) {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/accounts", func(w http.ResponseWriter, r *http.Request) {
		accounts := dev.Accounts()
		names := make([]string, 0, len(accounts))
		for name := range accounts {
			names = append(names, name)
		}
		sort.Strings(names)
		administrators := make([]map[string]string, 0, len(names))
		for _, name := range names {
			administrators = append(administrators, map[string]string{
				"name":    name,
				"profile": accounts[name].Profile,
				"vdom":    accounts[name].VDOM,
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"accounts":       names,
			"administrators": administrators,
		})
	})
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("serve /debug/accounts on %s: %w", addr, err)
	}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("fake-device: debug listener: %v", err)
		}
	}()
	return srv, nil
}

// splitList reads a comma-separated flag, ignoring empty entries.
func splitList(v string) []string {
	var out []string
	for _, part := range strings.Split(v, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func run() error {
	var (
		listen   = flag.String("listen", "0.0.0.0:22", "address to serve the device CLI on")
		hostname = flag.String("hostname", "FGT-E2E", "the hostname the CLI prompt is built from")
		admin    = flag.String("admin", "hoplock-mgmt", "the privileged administrator the proxy logs in as")
		password = flag.String("password", "", "that administrator's password (or $HOPLOCK_DEVICE_ADMIN_PASSWORD)")
		paging   = flag.Int("page-every", 0, "emit the pager's marker every n lines of show output; 0 disables paging")
		debug    = flag.String("debug", "", "serve GET /debug/accounts on this address; empty disables it")
		// The second unit. It is a LISTENER rather than a container of its own,
		// because a multi-VDOM FortiGate is the same appliance in a different
		// configuration — modelling it as a second node would say the estate has
		// two kinds of box when what it has is one box with virtual domains
		// (phase 0016, PLAN §5.3).
		vdomListen = flag.String("vdom-listen", "", "also serve a unit running virtual domains on this address; empty disables it")
		vdomMode   = flag.String("vdom-mode", sshtest.FortiOSVDOMMultiple, "the virtual domain configuration that unit reports")
		vdoms      = flag.String("vdoms", "", "comma-separated virtual domains that unit has; empty means the documented defaults for the mode")
		vdomDebug  = flag.String("vdom-debug", "", "serve that unit's GET /debug/accounts on this address; empty disables it")
		dump       = flag.String("dump", "", "client mode: fetch this device's administrator table from the given address and exit")
	)
	flag.Parse()

	// Client mode. It exists because the appliance sits on the topology's
	// INTERNAL network, where a published port is not reachable from the host
	// the scenario suite runs on — and putting the device on an externally
	// routable network to read a debug endpoint would weaken the very isolation
	// the device scenarios rely on. So the suite runs this binary INSIDE the
	// container instead (`docker compose exec device …`), which needs no extra
	// network, no published port, and no curl in the image.
	if *dump != "" {
		return dumpAccounts(*dump)
	}

	secret := *password
	if secret == "" {
		secret = os.Getenv("HOPLOCK_DEVICE_ADMIN_PASSWORD")
	}
	if secret == "" {
		return fmt.Errorf("no administrator password: pass -password or set HOPLOCK_DEVICE_ADMIN_PASSWORD")
	}

	dev, err := sshtest.StartFortiOSOn(*listen, sshtest.FortiOSOptions{
		Hostname:      *hostname,
		AdminUser:     *admin,
		AdminPassword: secret,
		// The device's own administrator, so the topology can assert that the
		// proxy only ever removes what it created.
		Accounts: []sshtest.FortiOSAccount{{Name: "admin", Profile: "super_admin"}},
		Faults:   sshtest.FortiOSFaults{PageEvery: *paging},
	})
	if err != nil {
		return err
	}
	defer func() { _ = dev.Close() }()

	logger := log.New(os.Stdout, "", log.LstdFlags|log.LUTC)
	logger.Printf("fake-device: serving the %s CLI on %s as %s", *hostname, dev.Addr(), *admin)

	if *vdomListen != "" {
		partitioned, err := sshtest.StartFortiOSOn(*vdomListen, sshtest.FortiOSOptions{
			Hostname:      *hostname + "-VDOM",
			AdminUser:     *admin,
			AdminPassword: secret,
			Accounts:      []sshtest.FortiOSAccount{{Name: "admin", Profile: "super_admin"}},
			VDOMMode:      *vdomMode,
			VDOMs:         splitList(*vdoms),
			Faults:        sshtest.FortiOSFaults{PageEvery: *paging},
		})
		if err != nil {
			return err
		}
		defer func() { _ = partitioned.Close() }()
		logger.Printf("fake-device: serving a %s unit (%v) on %s", *vdomMode, partitioned.VDOMs(), partitioned.Addr())
		if *vdomDebug != "" {
			srv, err := serveAccounts(*vdomDebug, partitioned)
			if err != nil {
				return err
			}
			defer func() { _ = srv.Close() }()
			logger.Printf("fake-device: serving that unit's /debug/accounts on %s", *vdomDebug)
		}
	}

	if *debug != "" {
		srv, err := serveAccounts(*debug, dev)
		if err != nil {
			return err
		}
		defer func() { _ = srv.Close() }()
		logger.Printf("fake-device: serving /debug/accounts on %s", *debug)
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	logger.Printf("fake-device: shutting down")
	return nil
}
