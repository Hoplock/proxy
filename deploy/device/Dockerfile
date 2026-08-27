# Copyright (c) 2026 Mauro Silva. All rights reserved.
# SPDX-License-Identifier: LicenseRef-Proprietary

# Runtime image for cmd/fake-device: the appliance node of the e2e topology
# (docs/PLAN.md §9, phase 0014).
#
# It stands in for a FortiGate. There is no way to put real network gear in CI,
# and "the devices are physical" would otherwise be a permanent excuse for the
# device credential method to be the one part of the system no real SSH client
# ever exercises. The CLI it speaks is the one internal/sshtest models, faults
# and paging included.
#
# The binary is built on the host (`make e2e-build`), like every other image
# here.
FROM debian:stable-slim

COPY bin/hoplock-fake-device /usr/local/bin/hoplock-fake-device

ENTRYPOINT ["/usr/local/bin/hoplock-fake-device"]
