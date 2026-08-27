// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

// Package device defines what a platform driver is: the seam an
// ephemeral-account provisioner plugs into to create, credential, remove, and
// enumerate short-lived administrators on a device the proxy cannot administer
// as a POSIX host (PLAN §5.3, D13).
//
// It holds interfaces, declarations, and a registry, and NOTHING THAT CONNECTS
// TO ANYTHING. Phase 0013 writes the seam down; phase 0014 writes the first
// driver and the provisioner that walks it. The package deliberately has no
// network code and no driver of its own, so that the shape can be reviewed
// before anything is built against it — the same order phase 0006 used for the
// policy vocabulary and phase 0009 for the inspection pipeline.
package device
