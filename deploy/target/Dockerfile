# Copyright (c) 2026 Mauro Silva. All rights reserved.
# SPDX-License-Identifier: LicenseRef-Proprietary

# The target node: a real sshd, a real account database, and the two things the
# two credential methods need from a target.
#
#   ephemeral-user (D6) needs a privileged provisioning account reachable with
#   the management certificate. That is root here, with the management key in
#   its authorized_keys — exactly the deployment prerequisite an operator has to
#   satisfy on a real fleet.
#
#   brokered-key (D6a) needs an account that ALREADY EXISTS and no provisioning
#   rights at all. That is netadmin: created once, by this image, standing in
#   for an appliance the proxy cannot administer. A scenario that finds it
#   modified has found a bug.
#
# Phase 0019 adds a third set of prerequisites: the ones an ENFORCEMENT RUNG
# needs (docs/PLAN.md §6.5). They are listed here rather than assumed, because
# the whole point of the capability probe is that a target either has them or
# the rung is refused:
#
#   account-restricted needs nothing but an sshd honouring authorized_keys
#   options, which this one does.
#
#   account-confined needs `setpriv` (util-linux, already present) and a kernel
#   that lets the provisioner bind-mount a home noexec,nosuid,nodev — which in a
#   container means CAP_SYS_ADMIN, granted in the compose files rather than here.
#
#   the two reach rungs need `iptables`/`ip6tables` with the owner and comment
#   matches, plus CAP_NET_ADMIN.
#
# `netcat-openbsd` is there for one reason: the reach rung's test has to open a
# socket from inside a confined session using a binary the EXECUTION rung
# permits, so the two axes can be shown to be independent.
#
# This image backs both `make test-sshd` (the phase-0007 credential tests) and
# the e2e topology.
FROM debian:stable-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server procps iproute2 \
    iptables netcat-openbsd util-linux \
 && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /run/sshd /root/.ssh /etc/ssh/sshd_config.d && chmod 700 /root/.ssh \
 && useradd -m -s /bin/sh netadmin \
 && mkdir -p /home/netadmin/.ssh && chmod 700 /home/netadmin/.ssh \
 && chown -R netadmin:netadmin /home/netadmin \
 && sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config \
 && grep -q '^Include /etc/ssh/sshd_config.d/\*.conf' /etc/ssh/sshd_config \
    || sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config

COPY target/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 755 /usr/local/bin/entrypoint.sh

EXPOSE 22
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
