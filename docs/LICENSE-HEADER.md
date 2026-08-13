# License header

Every `.go` file in this repository **must** begin with the following two lines,
verbatim, followed by a blank line and then the `package` clause (PLAN §8, D10):

```go
// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary
```

Notes:

- Copy the text exactly — CI checks it (see `make license-check` and the
  `license` job in `.github/workflows/ci.yml`).
- The header goes **above** any package doc comment, separated from the package
  doc comment by a blank line so the header is not absorbed into the doc.
- The year stays `2026` for existing files; new files use the year they were
  created.
- Non-Go files (YAML, Makefile, workflows) do not carry the header; the
  repository-level `LICENSE` covers them.
