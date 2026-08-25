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

ENTRYPOINT []
