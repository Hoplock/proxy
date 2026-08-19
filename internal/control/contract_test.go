// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package control

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// specPath is the contract this package implements. api/control.yaml is the
// source of truth, so these tests fail if the Go client and the document drift
// apart — a stale contract is worse than no contract.
const specPath = "../../api/control.yaml"

// readmePath is the contract's human-readable companion. It is what a fresh
// session reads first, so it is asserted against the same constants.
const readmePath = "../../api/README.md"

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
		checkResponses(t, "post "+path, op, success)
	}

	// The revocation stream is the one endpoint that is a long-lived GET rather
	// than a POST, so it is checked separately: no request body, and the gap
	// recovery parameter the client sends on reconnect must be documented.
	item, ok := paths[PathProxyEvents].(map[string]any)
	if !ok {
		t.Fatalf("%s documents no path %q", specPath, PathProxyEvents)
	}
	op, ok := item["get"].(map[string]any)
	if !ok {
		t.Fatalf("path %q has no get operation", PathProxyEvents)
	}
	checkResponses(t, "get "+PathProxyEvents, op, "200")
	params, _ := op["parameters"].([]any)
	documented := make(map[string]bool, len(params))
	for _, p := range params {
		if m, ok := p.(map[string]any); ok {
			name, _ := m["name"].(string)
			documented[name] = true
		}
	}
	for _, name := range []string{"proxy_id", QueryLastEventID} {
		if !documented[name] {
			t.Errorf("get %q does not document the %q parameter", PathProxyEvents, name)
		}
	}

	if got, want := len(paths), len(wantStatus)+1; got != want {
		t.Errorf("spec documents %d paths, client knows %d; keep them in step", got, want)
	}
}

// checkResponses asserts an operation documents both the success status the
// client expects and the deny response every endpoint can answer.
func checkResponses(t *testing.T, op string, operation map[string]any, success string) {
	t.Helper()
	responses, ok := operation["responses"].(map[string]any)
	if !ok {
		t.Errorf("%s has no responses", op)
		return
	}
	if _, ok := responses[success]; !ok {
		t.Errorf("%s does not document the %s success response the client expects", op, success)
	}
	if _, ok := responses["401"]; !ok {
		t.Errorf("%s does not document the 401 deny response", op)
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
		{"RevocationEvent", "type", []string{
			string(EventTypeSessionKill), string(EventTypeCacheInvalidate),
			string(EventTypeHeartbeat), string(EventTypeResync)}},
		{"LogRecord", "severity", []string{
			string(SeverityInfo), string(SeverityWarn), string(SeverityCritical)}},
		// The phase 0006 vocabulary (D5a, D6a, D11, D12).
		{"TargetAuth", "method", []string{
			string(TargetAuthEphemeralUser), string(TargetAuthBrokeredKey),
			string(TargetAuthStaticKey)}},
		{"FilterPolicy", "exec_mode", []string{
			string(ExecModeFiltered), string(ExecModeRestricted)}},
		{"RestrictedCommand", "form", []string{
			string(CommandFormExact), string(CommandFormPositional)}},
		{"ArgumentSpec", "kind", []string{
			string(ArgumentLiteral), string(ArgumentPrefix),
			string(ArgumentOneOf), string(ArgumentAny)}},
		{"HopMetadata", "connection", []string{
			string(HopConnectionDial), string(HopConnectionRelay)}},
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

// TestSpecItemEnumsMatchGoConstants covers the enums that live on an array's
// items rather than on the property itself. permitted_requests.types is one
// (its members are request names), and it is the axis most likely to be
// extended, so the document and the Request* constants are pinned together.
func TestSpecItemEnumsMatchGoConstants(t *testing.T) {
	doc := loadSpec(t)

	ref := "#/components/schemas/RequestPolicy/properties/types/items/enum"
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

	want := []string{RequestPTY, RequestShell, RequestExec, RequestEnv, RequestX11, RequestAuthAgent}
	if len(got) != len(want) {
		t.Errorf("enum has %d values, Go declares %d", len(got), len(want))
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("enum is missing the Go constant %q", w)
		}
	}
	// The one member that must NOT be there: a subsystem is permitted by name,
	// so listing "subsystem" as a type would mean "sftp and everything else".
	if got[RequestSubsystem] {
		t.Errorf("enum lists %q; subsystems are permitted by name in RequestPolicy.Subsystems",
			RequestSubsystem)
	}
}

// TestSpecDocumentsTheV2PolicySchemas keeps the AuthorizeResponse properties
// and the Go struct tags in step. A field the document does not carry is a
// field a server has no reason to send.
func TestSpecDocumentsTheV2PolicySchemas(t *testing.T) {
	doc := loadSpec(t)

	for field, schema := range map[string]string{
		"permitted_requests":        "RequestPolicy",
		"permitted_forwards":        "ForwardPolicy",
		"permitted_global_requests": "GlobalRequestPolicy",
		"target_auth":               "TargetAuth",
	} {
		ref := "#/components/schemas/AuthorizeResponse/properties/" + field + "/$ref"
		node, ok := resolveRef(doc, ref)
		if !ok {
			t.Errorf("AuthorizeResponse does not document %q", field)
			continue
		}
		if got, want := node, "#/components/schemas/"+schema; got != want {
			t.Errorf("AuthorizeResponse.%s = %v, want %s", field, got, want)
		}
	}

	// The properties that are not $refs, checked for presence.
	for schema, field := range map[string]string{
		"AuthorizeRequest":   "policy_version",
		"FilterPolicy":       "restricted_exec",
		"HopMetadata":        "next_proxy_id",
		"ForwardPolicy":      "forwarded_tcpip",
		"ForwardDestination": "port_range",
	} {
		ref := "#/components/schemas/" + schema + "/properties/" + field
		if _, ok := resolveRef(doc, ref); !ok {
			t.Errorf("%s does not document %q", schema, field)
		}
	}
}

// TestReadmeDocumentsTheContract guards the companion document. api/README.md
// is what a session reads before the OpenAPI file, so a vocabulary it does not
// mention is a vocabulary the next phase will not know exists.
func TestReadmeDocumentsTheContract(t *testing.T) {
	raw, err := os.ReadFile(readmePath)
	if err != nil {
		t.Fatalf("read %s: %v", readmePath, err)
	}
	readme := string(raw)

	// Every path the client dials, spelled exactly as the client dials it.
	for _, path := range []string{
		PathAuthenticateCert, PathAuthenticatePassword, PathPollMFA, PathAuthorize,
		PathReportHostKey, PathIngestLogBatch, PathIngestPriorityLog, PathProxyEvents,
	} {
		if !strings.Contains(readme, path) {
			t.Errorf("%s does not document the path %q", readmePath, path)
		}
	}

	// Every field and enum value the phase 0006 vocabulary added, by the name
	// that appears on the wire.
	for _, name := range []string{
		"policy_version", "permitted_requests", "permitted_forwards",
		"permitted_global_requests", "target_auth", "exec_mode",
		"restricted_exec", "next_proxy_id", "subsystems",
		"direct_tcpip", "forwarded_tcpip", "port_range",
		string(TargetAuthEphemeralUser), string(TargetAuthBrokeredKey),
		string(TargetAuthStaticKey),
		string(ExecModeFiltered), string(ExecModeRestricted),
		string(CommandFormExact), string(CommandFormPositional),
		string(ArgumentLiteral), string(ArgumentPrefix), string(ArgumentOneOf),
		string(ArgumentAny),
		string(HopConnectionDial), string(HopConnectionRelay),
	} {
		if !strings.Contains(readme, name) {
			t.Errorf("%s does not document %q", readmePath, name)
		}
	}
}
