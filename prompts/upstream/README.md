# Upstream requests

**Always empty here.** An upstream request is a need a repository raises for the
one above it (`docs/CROSS-REPO-PROTOCOL.md` §3.2, §4.2), and nothing is above
the proxy. Requests arrive here instead: they wait in `hoplock/control`'s
`prompts/upstream/queued/`, and answering one queues a prompt in this
repository's `prompts/queued/`.

The folder exists so that all three repositories have one layout and are
searched one way (§4.3). `test/docs/indexes_test.go` keeps it empty.
