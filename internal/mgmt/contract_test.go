// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package mgmt

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// specPath is the contract this package implements. api/management.yaml is the
// source of truth, so these tests fail if the Go client and the document drift
// apart — a stale contract is worse than no contract.
const specPath = "../../api/management.yaml"

// loadSpec decodes the OpenAPI document into a generic tree.
func loadSpec(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatalf("read %s: %v", specPath, err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("%s is not valid YAML: %v", specPath, err)
	}
	return doc
}

func TestSpecIsOpenAPI3(t *testing.T) {
	doc := loadSpec(t)

	version, _ := doc["openapi"].(string)
	if !strings.HasPrefix(version, "3.") {
		t.Fatalf("openapi = %q, want a 3.x version", version)
	}
	for _, key := range []string{"info", "paths", "components"} {
		if _, ok := doc[key]; !ok {
			t.Errorf("%s has no top-level %q", specPath, key)
		}
	}
	info, ok := doc["info"].(map[string]any)
	if !ok {
		t.Fatal("info is not an object")
	}
	for _, key := range []string{"title", "version"} {
		if s, _ := info[key].(string); s == "" {
			t.Errorf("info.%s is required", key)
		}
	}
}

func TestSpecDocumentsEveryClientPath(t *testing.T) {
	doc := loadSpec(t)
	paths, ok := doc["paths"].(map[string]any)
	if !ok {
		t.Fatal("paths is not an object")
	}

	// Every path the client dials must be documented, with the pieces a caller
	// needs: a request body and both the success and the deny response.
	wantStatus := map[string]string{
		PathAuthenticateCert:     "200",
		PathAuthenticatePassword: "200",
		PathPollMFA:              "200",
		PathAuthorize:            "200",
		PathReportHostKey:        "200",
		PathIngestLogBatch:       "202",
		PathIngestPriorityLog:    "200",
	}

	for path, success := range wantStatus {
		item, ok := paths[path].(map[string]any)
		if !ok {
			t.Errorf("%s documents no path %q", specPath, path)
			continue
		}
		op, ok := item["post"].(map[string]any)
		if !ok {
			t.Errorf("path %q has no post operation", path)
			continue
		}
		if _, ok := op["requestBody"]; !ok {
			t.Errorf("post %q has no requestBody", path)
		}
		responses, ok := op["responses"].(map[string]any)
		if !ok {
			t.Errorf("post %q has no responses", path)
			continue
		}
		if _, ok := responses[success]; !ok {
			t.Errorf("post %q does not document the %s success response the client expects", path, success)
		}
		if _, ok := responses["401"]; !ok {
			t.Errorf("post %q does not document the 401 deny response", path)
		}
	}

	if got, want := len(paths), len(wantStatus); got != want {
		t.Errorf("spec documents %d paths, client knows %d; keep them in step", got, want)
	}
}

func TestSpecReferencesAllResolve(t *testing.T) {
	doc := loadSpec(t)
	for _, ref := range collectRefs(doc) {
		if !strings.HasPrefix(ref, "#/") {
			t.Errorf("$ref %q is not a local reference; the contract must be self-contained", ref)
			continue
		}
		if _, ok := resolveRef(doc, ref); !ok {
			t.Errorf("$ref %q does not resolve", ref)
		}
	}
}

// TestSpecEnumsMatchGoConstants keeps the wire values in the document and the
// constants callers switch on from drifting apart.
func TestSpecEnumsMatchGoConstants(t *testing.T) {
	doc := loadSpec(t)

	tests := []struct {
		schema   string
		property string
		want     []string
	}{
		{"AuthenticateResponse", "status", []string{
			string(AuthStatusAuthenticated), string(AuthStatusMFARequired)}},
		{"AuthorizeRequest", "auth_method", []string{
			string(AuthMethodCert), string(AuthMethodPasswordMFA)}},
		{"AuthorizeResponse", "route_type", []string{
			string(RouteTypeDirect), string(RouteTypeNextHop)}},
		{"FilterPolicy", "mode", []string{
			string(FilterModeWhitelist), string(FilterModeBlacklist)}},
		{"FilterRule", "action", []string{
			string(FilterActionAllowAndLog), string(FilterActionBlockCommand),
			string(FilterActionWarnAndContinue), string(FilterActionKillSession)}},
		{"HostKeyReportResponse", "decision", []string{
			string(HostKeyAccept), string(HostKeyReject)}},
		{"LogRecord", "severity", []string{
			string(SeverityInfo), string(SeverityWarn), string(SeverityCritical)}},
	}

	for _, tc := range tests {
		t.Run(tc.schema+"."+tc.property, func(t *testing.T) {
			ref := "#/components/schemas/" + tc.schema + "/properties/" + tc.property + "/enum"
			node, ok := resolveRef(doc, ref)
			if !ok {
				t.Fatalf("%s has no enum", ref)
			}
			values, ok := node.([]any)
			if !ok {
				t.Fatalf("%s is not a list", ref)
			}
			got := make(map[string]bool, len(values))
			for _, v := range values {
				s, _ := v.(string)
				got[s] = true
			}
			if len(got) != len(tc.want) {
				t.Errorf("enum has %d values, Go declares %d", len(got), len(tc.want))
			}
			for _, want := range tc.want {
				if !got[want] {
					t.Errorf("enum is missing the Go constant %q", want)
				}
			}
		})
	}
}

// collectRefs walks a decoded document and returns every $ref value in it.
func collectRefs(node any) []string {
	var refs []string
	switch n := node.(type) {
	case map[string]any:
		for k, v := range n {
			if k == "$ref" {
				if s, ok := v.(string); ok {
					refs = append(refs, s)
				}
				continue
			}
			refs = append(refs, collectRefs(v)...)
		}
	case []any:
		for _, v := range n {
			refs = append(refs, collectRefs(v)...)
		}
	}
	return refs
}

// resolveRef follows a local JSON pointer such as
// "#/components/schemas/Identity" through the decoded document.
func resolveRef(doc map[string]any, ref string) (any, bool) {
	var node any = doc
	for _, part := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
		obj, ok := node.(map[string]any)
		if !ok {
			return nil, false
		}
		node, ok = obj[part]
		if !ok {
			return nil, false
		}
	}
	return node, true
}

// TestPasswordRequestRedactsThePassword guards PLAN §7: the initial-auth
// password must never reach a log, including through an accidental %v of the
// request struct.
func TestPasswordRequestRedactsThePassword(t *testing.T) {
	req := AuthenticatePasswordRequest{
		Login:    "alice",
		Target:   "host.company.com",
		Password: "hunter2",
		Conn:     testConn(),
	}

	for _, format := range []string{"%v", "%s", "%+v", "%#v"} {
		if got := fmt.Sprintf(format, req); strings.Contains(got, "hunter2") {
			t.Errorf("%s of the request leaked the password: %s", format, got)
		}
	}
	// A pointer formats via the same methods, since they have value receivers.
	if got := fmt.Sprintf("%v", &req); strings.Contains(got, "hunter2") {
		t.Errorf("%%v of a *request leaked the password: %s", got)
	}

	// The password must still reach the server on the wire.
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(body), `"password":"hunter2"`) {
		t.Errorf("JSON body = %s, want the password sent to the server", body)
	}
}
