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
	chown "$owner" "$dest"
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

exec /usr/sbin/sshd -D -e
