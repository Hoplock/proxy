#!/bin/sh
# Copyright (c) 2026 Mauro Silva. All rights reserved.
# SPDX-License-Identifier: LicenseRef-Proprietary
#
# SSH_ASKPASS helper for the password+MFA scenarios (phase 0026).
#
# OpenSSH will not take a keyboard-interactive answer from stdin: read_passphrase
# opens /dev/tty, and `docker compose exec -T` gives the client none. SSH_ASKPASS
# is the supported way to answer one without a terminal, and since OpenSSH 8.4
# SSH_ASKPASS_REQUIRE=force is what makes the client use it with no X11 display.
#
# It echoes HOPLOCK_PASSWORD and ignores the prompt text it is handed in $1. That
# is deliberate: an askpass program could answer different questions differently,
# and one that did would hide from the scenario which question the proxy actually
# asked. Answering exactly one thing means a client that was asked something
# unexpected fails instead of quietly succeeding.
printf '%s\n' "$HOPLOCK_PASSWORD"
