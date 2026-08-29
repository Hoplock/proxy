#!/bin/sh
# Copyright (c) 2026 Mauro Silva. All rights reserved.
# SPDX-License-Identifier: LicenseRef-Proprietary

# Install the two authorized keys from the mounted material and start sshd.
#
# The keys are mounted at run time rather than baked into the image for the same
# reason the host keys are generated at start: material inside an image is
# material shared by everyone who has the image.
set -eu

install_key() {
	src=$1 dest=$2 owner=$3
	if [ ! -f "$src" ]; then
		echo "target: missing $src — run deploy/gen-material.sh" >&2
		exit 1
	fi
	cat "$src" > "$dest"
	chmod 600 "$dest"
	# The DIRECTORY's ownership matters as much as the file's: sshd's StrictModes
	# refuses a key under an .ssh someone else owns, and reports it only in the
	# target's own log — at the proxy it is an indistinguishable
	# "unable to authenticate".
	chown "$owner" "$dest" "$(dirname "$dest")"
}

# ephemeral-user (D6): the management certificate's key, on the provisioning
# account.
install_key /material/management_key.pub /root/.ssh/authorized_keys root:root
# brokered-key (D6a): the credential for the account that already exists.
install_key /material/brokered_key.pub /home/netadmin/.ssh/authorized_keys netadmin:netadmin

# Generated at start rather than at build: a host key baked into an image is a
# host key shared by everyone who pulls it. Trust-on-first-use (D7) is what the
# proxy applies to it.
ssh-keygen -A >/dev/null

# A decrypting proxy is a SINGLE SOURCE ADDRESS to every target it fronts. That
# is not incidental, it is the deployment model — and it collides with sshd's
# per-source abuse defences, which exist to slow down many distinct attackers
# rather than one trusted enforcement point.
#
# OpenSSH 9.8's PerSourcePenalties is the sharp one. Anything that makes the
# proxy's credential fail against a target — a stale brokered key, a rotated
# management certificate, an authorized_keys the account cannot read — is scored
# as a failed authentication against the PROXY's address, not against the user
# who happened to trigger it. A handful of those and sshd stops answering the
# proxy at all:
#
#   drop connection #0 from [proxy] on [target]:22 penalty: failed authentication
#
# which surfaces at the proxy as a bare "connection reset by peer" and looks
# like a network fault. One misconfigured route becomes an outage for every user
# of that target. Phase 0012 hit exactly this (a .ssh directory owned by root),
# and prompt 0020 is the proxy-side answer.
#
# Turning it off is right for a target reachable ONLY through a proxy: the
# defence has no distinct sources left to distinguish. It also keeps the e2e
# suite honest — phase 0020's containment scenarios have to be proven by the
# proxy's own behaviour, not by the target giving up on it. A real fleet needs
# the same decision made deliberately.
#
# Each directive is applied only if this sshd understands it, so a base image
# with an older (or newer) OpenSSH still starts rather than failing to boot on
# an unknown keyword.
conf=/etc/ssh/sshd_config.d/hoplock.conf
: > "$conf"
for directive in \
	"PerSourcePenalties no" \
	"PerSourceMaxStartups none" \
	"MaxStartups 200:30:400" \
	"MaxSessions 100"
do
	printf '%s\n' "$directive" >> "$conf"
	if ! /usr/sbin/sshd -t >/dev/null 2>&1; then
		echo "target: this sshd does not understand \"$directive\"; skipping it" >&2
		sed -i '$d' "$conf"
	fi
done

exec /usr/sbin/sshd -D -e
