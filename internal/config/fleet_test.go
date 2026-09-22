// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package config

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

func loadExample(t *testing.T) *Config {
	t.Helper()
	cfg, err := Load(exampleConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func settings(kv map[string]string) map[string]json.RawMessage {
	out := make(map[string]json.RawMessage, len(kv))
	for k, v := range kv {
		out[k] = json.RawMessage(v)
	}
	return out
}

// TestAFleetDocumentCannotSetABootstrapSetting is the rule that stops a bad push
// orphaning a proxy: nothing the proxy needs to reach Control, no path to local
// material, and no listener can be set remotely. A document naming one is
// rejected WHOLE — its legitimate settings are not applied either.
func TestAFleetDocumentCannotSetABootstrapSetting(t *testing.T) {
	boot := loadExample(t)
	for _, key := range []string{
		"proxy.id", "proxy.listen_addr", "proxy.host_key_path",
		"control.base_url", "control.token", "control.cache.stale_after",
		"logging.buffer_dir", "routing.target_delimiter",
		"chain.identity_key_path", "chain.upstream.host_key_path",
		"chain.accept.listen_addr", "chain.accept.authorized_keys_path",
		"auth.user.methods", "auth.target.method", "auth.target.static_key.key_path",
		"no.such.setting",
	} {
		t.Run(key, func(t *testing.T) {
			var liveCalls int
			f := NewFleet(boot, boot, func(*Config) { liveCalls++ })
			doc := settings(map[string]string{
				key:                     `"https://attacker.example.com"`,
				"control.cache.max_ttl": `"1m"`,
			})
			if _, err := boot.WithFleet(doc); !errors.Is(err, ErrNotFleetOwned) {
				t.Fatalf("WithFleet: err = %v, want ErrNotFleetOwned", err)
			}
			if _, err := f.ApplyConfig(doc); !errors.Is(err, ErrNotFleetOwned) {
				t.Fatalf("ApplyConfig: err = %v, want ErrNotFleetOwned", err)
			}
			if liveCalls != 0 || f.Current() != boot {
				t.Error("a rejected document applied its fleet-owned half")
			}
		})
	}
}

func TestFleetDocumentsAreAppliedWholeOrNotAtAll(t *testing.T) {
	boot := loadExample(t)
	for name, doc := range map[string]map[string]string{
		"wrong type":                   {"control.cache.max_ttl": `300`, "session.deadline_warning": `"2m"`},
		"not a duration":               {"control.cache.max_ttl": `"soon"`},
		"null":                         {"session.deadline_warning": `null`},
		"float for int":                {"chain.max_hops": `2.5`},
		"fails validation":             {"control.cache.max_entries": `-1`},
		"inconsistent whole":           {"logging.retry_min": `"1m"`, "logging.retry_max": `"1s"`},
		"address without upstream key": {"chain.upstream.address": `"up.example.com:2223"`},
	} {
		t.Run(name, func(t *testing.T) {
			var liveCalls int
			f := NewFleet(boot, boot, func(*Config) { liveCalls++ })
			if _, err := f.ApplyConfig(settings(doc)); err == nil {
				t.Fatal("document applied")
			}
			if liveCalls != 0 {
				t.Error("live settings were pushed from a rejected document")
			}
		})
	}
}

func TestFleetErrorsNameKeysNotValues(t *testing.T) {
	boot := loadExample(t)
	_, err := boot.WithFleet(settings(map[string]string{"control.cache.max_ttl": `"s3cr3t-looking-value"`}))
	if err == nil || strings.Contains(err.Error(), "s3cr3t") || !strings.Contains(err.Error(), "control.cache.max_ttl") {
		t.Errorf("err = %v; want the key named and the value absent", err)
	}
}

func TestFleetAppliesLiveSettingsAndHoldsRestartOnes(t *testing.T) {
	boot := loadExample(t)
	var pushed *Config
	f := NewFleet(boot, boot, func(c *Config) { pushed = c })

	restart, err := f.ApplyConfig(settings(map[string]string{
		"control.cache.max_ttl":    `"2m"`,
		"session.deadline_warning": `"30s"`,
	}))
	if err != nil || len(restart) != 0 {
		t.Fatalf("live document: restart=%v err=%v", restart, err)
	}
	if pushed == nil || pushed.Control.Cache.MaxTTL != 2*time.Minute || pushed.Session.DeadlineWarning != 30*time.Second {
		t.Fatalf("live settings not pushed: %+v", pushed)
	}
	if boot.Control.Cache.MaxTTL != 0 {
		t.Error("WithFleet modified the bootstrap configuration")
	}

	pushed = nil
	restart, err = f.ApplyConfig(settings(map[string]string{
		"control.cache.max_ttl": `"1m"`,
		"logging.batch_size":    `128`,
	}))
	if err != nil || !slices.Equal(restart, []string{"logging.batch_size"}) {
		t.Fatalf("restart document: restart=%v err=%v", restart, err)
	}
	if pushed != nil || f.Current().Control.Cache.MaxTTL != 2*time.Minute {
		t.Error("a document needing a restart applied its live half; the process must run exactly one document")
	}

	// Withdrawing the document returns every fleet-owned setting to the file.
	restart, err = f.ApplyConfig(nil)
	if err != nil || len(restart) != 0 || pushed == nil || pushed.Control.Cache.MaxTTL != boot.Control.Cache.MaxTTL {
		t.Errorf("unpublished: restart=%v err=%v pushed=%v", restart, err, pushed)
	}
}

// TestARestartSettingStartedFromTheDocumentIsNotPending: the comparison is with
// what the process was BUILT from, so the document evaluated at startup is
// running, not pending.
func TestARestartSettingStartedFromTheDocumentIsNotPending(t *testing.T) {
	boot := loadExample(t)
	doc := settings(map[string]string{"logging.batch_size": `128`})
	started, err := boot.WithFleet(doc)
	if err != nil {
		t.Fatal(err)
	}
	f := NewFleet(boot, started, nil)
	if restart, err := f.ApplyConfig(doc); err != nil || len(restart) != 0 {
		t.Errorf("restart=%v err=%v; want the startup document applied", restart, err)
	}
}

// TestEveryFleetSettingIsARealKey keeps the table's dotted keys in step with the
// YAML schema: a key that names no field is one no document could ever set.
func TestEveryFleetSettingIsARealKey(t *testing.T) {
	paths := map[string]bool{}
	var walk func(t reflect.Type, prefix string)
	walk = func(t reflect.Type, prefix string) {
		for i := range t.NumField() {
			f := t.Field(i)
			tag := strings.Split(f.Tag.Get("yaml"), ",")[0]
			if tag == "" || tag == "-" {
				continue
			}
			p := prefix + tag
			paths[p] = true
			if f.Type.Kind() == reflect.Struct && f.Type != reflect.TypeFor[time.Duration]() {
				walk(f.Type, p+".")
			}
		}
	}
	walk(reflect.TypeFor[Config](), "")
	for _, s := range FleetSettings() {
		if !paths[s.Key] {
			t.Errorf("fleet setting %q is not a key of the bootstrap schema", s.Key)
		}
	}
}

// TestTheExampleFileMarksEveryFleetSetting: D18 says which side a setting is on
// where an operator reads about that setting, not only in a list. The example
// file marks exactly the fleet-owned settings, with the right mode.
func TestTheExampleFileMarksEveryFleetSetting(t *testing.T) {
	f, err := os.Open(exampleConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	markerRe := regexp.MustCompile(`^\s*# \[fleet: (live|restart)\]$`)
	keyRe := regexp.MustCompile(`^(\s*)([a-z_]+):`)
	type frame struct {
		indent int
		key    string
	}
	var stack []frame
	pending := ""
	marked := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if m := markerRe.FindStringSubmatch(line); m != nil {
			pending = m[1]
			continue
		}
		m := keyRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		indent := len(m[1])
		for len(stack) > 0 && stack[len(stack)-1].indent >= indent {
			stack = stack[:len(stack)-1]
		}
		stack = append(stack, frame{indent, m[2]})
		if pending != "" {
			keys := make([]string, len(stack))
			for i, fr := range stack {
				keys[i] = fr.key
			}
			marked[strings.Join(keys, ".")] = pending
			pending = ""
		}
	}

	want := map[string]string{}
	for _, s := range FleetSettings() {
		want[s.Key] = map[bool]string{true: "live", false: "restart"}[s.Live]
	}
	if !reflect.DeepEqual(marked, want) {
		t.Errorf("config.example.yaml marks %v;\nthe fleet table says %v", marked, want)
	}
}
