// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"time"
)

// relayRegistrationReport is the part of a hub's last relay-registration report
// the scenario reads (api/control.yaml, RelayRegistrationReport, as the mock's
// GET /debug/relay-registrations returns it).
type relayRegistrationReport struct {
	RegisteredProxyIDs []string `json:"registered_proxy_ids"`
}

// relayRegistrationsOf is the last relay-registration report from one hub.
func relayRegistrationsOf(hub string) (relayRegistrationReport, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+controlAddr+"/debug/relay-registrations", nil)
	if err != nil {
		return relayRegistrationReport{}, false
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return relayRegistrationReport{}, false
	}
	defer func() { _ = resp.Body.Close() }()
	var all map[string]relayRegistrationReport
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&all) != nil {
		return relayRegistrationReport{}, false
	}
	rep, ok := all[hub]
	return rep, ok
}

// hubReports says whether hub's last report names id.
func hubReports(hub, id string) bool {
	rep, ok := relayRegistrationsOf(hub)
	return ok && slices.Contains(rep.RegisteredProxyIDs, id)
}
