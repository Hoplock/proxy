// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

package logging

import (
	"slices"
	"strings"

	"github.com/hoplock/proxy/internal/control"
)

// AlgorithmPolicyAttrs stamps the route's algorithm policy IN FORCE on a record
// (phases 0043, 0045): the profile always, the default included; the floor only
// when there is one; and one `algorithm_bans.<axis>` attribute per banned axis.
//
// It is one function because four records carry the policy — the provisioning
// record, the negotiated-algorithms record, the unmet-policy record and the
// device mapping event — and a policy spelled four ways is four chances for one
// of them to disagree with the handshake it describes.
func AlgorithmPolicyAttrs(attrs Attrs, policy control.AlgorithmPolicy) Attrs {
	attrs = attrs.Set(AttrAlgorithmProfile, string(policy.Profile.Resolve()))
	if policy.Floor != "" {
		attrs = attrs.Set(AttrAlgorithmFloor, string(policy.Floor))
	}
	if policy.Bans != nil {
		for _, axis := range control.BanAxes(*policy.Bans) {
			if len(axis.Names) == 0 {
				continue
			}
			names := slices.Clone(axis.Names)
			slices.Sort(names)
			attrs = attrs.Set(AttrAlgorithmBansPrefix+axis.Name, strings.Join(names, ","))
		}
	}
	return attrs
}
