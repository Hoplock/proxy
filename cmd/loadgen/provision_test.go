// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package main

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

func TestProvisioningRefusesWithoutRoot(t *testing.T) {
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		t.Skip("running as root: the refusal path cannot be exercised")
	}
	sc := decode(t, "name: x\nkind: provisioning\nprovisioning:\n  cycles: 1\n  concurrency: [1]\n")
	_, err := runProvisioning(context.Background(), sc)
	if err == nil {
		t.Fatal("runProvisioning succeeded without root")
	}
	// Creating accounts is not something to attempt and half-finish.
	if !strings.Contains(err.Error(), "root") && !strings.Contains(err.Error(), "Linux") {
		t.Errorf("error = %v, want it to name the missing precondition", err)
	}
}

func TestOneCycleLeavesNothingBehind(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("needs root on Linux: it creates and removes a real account")
	}
	if _, err := exec.LookPath("useradd"); err != nil {
		t.Skip("useradd not on PATH")
	}
	sc := decode(t, "name: x\nkind: provisioning\nprovisioning:\n  cycles: 1\n  concurrency: [1]\n  home: true\n  authorized_keys: true\n  prefix: hl-unittest\n")
	const name = "hl-unittest-0-0"
	create, key, remove, err := oneCycle(context.Background(), sc, name)
	if err != nil {
		t.Fatalf("oneCycle: %v", err)
	}
	if create <= 0 || remove <= 0 {
		t.Errorf("create=%v remove=%v, want both timed", create, remove)
	}
	if key <= 0 {
		t.Errorf("key write = %v, want it timed when authorized_keys is set", key)
	}
	// A harness that leaves accounts behind poisons the next run's numbers and
	// the machine it ran on.
	if out, err := exec.Command("id", name).CombinedOutput(); err == nil {
		t.Errorf("account %s still exists after the cycle: %s", name, out)
	}
	if _, err := os.Stat("/home/" + name); !os.IsNotExist(err) {
		t.Errorf("/home/%s still exists after the cycle", name)
	}
}

func TestNSSBackendIsReported(t *testing.T) {
	// A provisioning number that does not say which NSS backend it was taken
	// on is not usable: a directory-backed fleet does not behave like a
	// flat-file one.
	if got := nssPasswdBackend(); got == "" {
		t.Error("nssPasswdBackend returned empty; want a value or \"unknown\"")
	}
}
