# Copyright (c) 2026 Mauro Silva. All rights reserved.
# SPDX-License-Identifier: LicenseRef-Proprietary

# Runtime image for cmd/mock-control in the e2e topology (D3). See
# deploy/proxy/Dockerfile for why the binary is built on the host.
FROM debian:stable-slim

RUN mkdir -p /var/log/hoplock

COPY bin/mock-control /usr/local/bin/mock-control

ENTRYPOINT ["/usr/local/bin/mock-control"]
