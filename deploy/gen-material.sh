#!/bin/sh
# Copyright (c) 2026 Mauro Silva. All rights reserved.
# SPDX-License-Identifier: LicenseRef-Proprietary

# Generate the key material the e2e topology runs on, and render the mock
# Hoplock Control fixtures that refer to it by fingerprint.
#
# Nothing here is committed: the fixtures name keys by SHA256 fingerprint, so
# the fixture file cannot be written until the keys exist. Regenerating is
# cheap and always safe — every consumer mounts deploy/keys at run time rather
# than baking it into an image, which is also why no image has to be rebuilt
# when this runs again.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
keys="$here/keys"

rm -rf "$keys"
mkdir -p "$keys" "$keys/brokered"

gen() {
	ssh-keygen -q -t ed25519 -N "" -C "hoplock-e2e-$1" -f "$keys/$1"
}

# Users. Their fingerprints are what the fixtures accept for certificate auth.
gen user_alice
gen user_svc

# Each proxy's SSH host key, and the identity it presents to other proxies.
gen hostkey_proxy_direct
gen hostkey_proxy_nexthop
gen hostkey_proxy_zone
gen chain_proxy_direct
gen chain_proxy_nexthop
gen chain_proxy_zone

# proxy → target material: the management certificate's key (ephemeral-user,
# D6) and one brokered credential (brokered-key, D6a).
gen management_key
gen brokered_key
cp "$keys/brokered_key" "$keys/brokered/appliance-fleet.key"
chmod 600 "$keys/brokered/appliance-fleet.key"

# The relay hub's authorized_keys. The COMMENT is the proxy id the key may
# register as — a key naming no id could register as any proxy and start
# receiving its sessions (config.example.yaml, chain.accept).
sed 's/ hoplock-e2e-chain_proxy_zone$/ proxy-zone/' \
	"$keys/chain_proxy_zone.pub" > "$keys/relay_authorized_keys"

fingerprint() {
	ssh-keygen -lf "$keys/$1.pub" | awk '{print $2}'
}

# The fixtures are rendered rather than committed because a fingerprint is not
# knowable until its key exists. "|" is safe as a sed delimiter: a SHA256
# fingerprint is base64, which uses "+" and "/" but never "|".
sed \
	-e "s|@@FP_USER_ALICE@@|$(fingerprint user_alice)|" \
	-e "s|@@FP_USER_SVC@@|$(fingerprint user_svc)|" \
	-e "s|@@FP_CHAIN_DIRECT@@|$(fingerprint chain_proxy_direct)|" \
	-e "s|@@FP_CHAIN_NEXTHOP@@|$(fingerprint chain_proxy_nexthop)|" \
	-e "s|@@FP_CHAIN_ZONE@@|$(fingerprint chain_proxy_zone)|" \
	"$here/control/fixtures.template.yaml" > "$here/control/fixtures.yaml"

echo "e2e material generated in $keys"
