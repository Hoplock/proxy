# Downstream syncs

Syncs this repository's merged changes owe the repositories that consume them
(`docs/CROSS-REPO-PROTOCOL.md` §3.1, §4.1, §4.3). Each file is the "Downstream
sync" block from `docs/KICKOFF.md`, filled in and queued by the PR that owes it.

- **The work is done in `hoplock/control`** — and in `hoplock/enterprise` too
  when the change is to `docs/CROSS-REPO-PROTOCOL.md`, the one proxy surface
  Enterprise carries.
- **Named `proxy-PR#<n>-<short-description>.md`**, after the PR that queued it,
  and committed to that PR once it is open.
- **Waiting from the moment that PR merges.** Nothing here is numbered, and the
  default kickoff never reaches it: the "Next cross-repo request" kickoff in
  `docs/KICKOFF.md` answers the oldest request across all three repositories, in
  a session with all three checked out.
- **Moved to `implemented/`**, unchanged, by a PR here that merges after every
  sync PR that answered it.
