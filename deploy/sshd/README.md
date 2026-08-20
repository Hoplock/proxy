# A real sshd for the credential tests

`make test-sshd` builds and starts this container, points
`internal/auth/target`'s sshd tests at it, and tears it down again.

It exists because the rest of that package's tests run against a fake host whose
account database is a text file. That fake is the right trade for tests that
must run anywhere, and it cannot answer the questions only a real sshd can:
whether the account the proxy creates actually **accepts** the key it installed
(StrictModes, home ownership, `authorized_keys` permissions), and whether
`useradd` behaves the way the provisioning scripts assume.

What the image provides, and why each is a real deployment prerequisite:

| Provided | For | Prerequisite it stands for |
| --- | --- | --- |
| `root` reachable with the management key | `ephemeral-user` (D6) | the privileged provisioning account and the preloaded management certificate |
| `netadmin`, created once by the image | `brokered-key` (D6a) | an account that already exists on a device the proxy cannot administer |

The keys are generated per run into `keys/` and are **never committed** — see
`.gitignore`. Phase 0012 folds this container into the full e2e topology and
runs the tests in CI; until then the tests skip unless `HOPLOCK_TEST_SSHD_ADDR`
is set, which `make test-sshd` does.
