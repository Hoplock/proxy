# Copyright (c) 2026 Mauro Silva. All rights reserved.
# SPDX-License-Identifier: LicenseRef-Proprietary

# Runtime image for cmd/proxy in the e2e topology.
#
# The binary is built on the host (`make e2e-build`) rather than in a builder
# stage: the module cache and toolchain are already there, in CI as well as
# locally, and a second Go environment inside Docker would only be a second
# thing to keep pinned to docs/PLAN.md §8's version policy.
FROM debian:stable-slim

# The proxy holds keys and writes its telemetry buffer here.
RUN mkdir -p /var/lib/hoplock/logbuf

COPY bin/hoplock-proxy /usr/local/bin/hoplock-proxy

ENTRYPOINT ["/usr/local/bin/hoplock-proxy"]
