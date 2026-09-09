# Copyright (c) 2026 Mauro Silva. All rights reserved.
# SPDX-License-Identifier: LicenseRef-Proprietary

# The user node: a real OpenSSH client, and nothing else.
#
# The scenarios are driven from the host, but every SSH client invocation runs
# HERE — on a container attached only to the `edge` network. That is what makes
# "the target is reachable only through a proxy" a property of the test rather
# than a promise: this node has no route to the target at all.
#
# A real client, not a Go SSH library, because the acceptance criteria are about
# what a person at a terminal is told (docs/PLAN.md §4.3). Banners, channel
# rejection reasons, and exit statuses are asserted as OpenSSH renders them.
FROM debian:stable-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-client ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# The keyboard-interactive answering machine the password+MFA scenarios need;
# see askpass.sh for why a helper program is the only way in without a terminal.
COPY user/askpass.sh /usr/local/bin/hoplock-askpass
RUN chmod 0755 /usr/local/bin/hoplock-askpass

ENTRYPOINT []
