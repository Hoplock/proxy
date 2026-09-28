# 0047 — Declare what each algorithm profile offers, per axis — Learnings

## Summary
- What shipped: `AuthorizeRequest.capabilities.algorithm_profiles`, one flat `AlgorithmProfileCapability` per accepted profile: `profile` beside `key_exchanges`, `ciphers`, `macs`, `host_keys`, `public_key_auth`, **every axis required**. The lists are **before any floor or ban**, and key exchanges are **alias-complete**. It is derived by `control.AlgorithmProfileCapabilities()` from `AlgorithmPolicy{Profile: p}` and sent by `target.ProxyCapabilities()` on every authorize.
- Key files: `api/{control.yaml,README.md}`, `internal/control/{algorithms,enforcement,clone,policy}.go`, `internal/control/declaration_test.go` (new), `internal/auth/target/enforcement.go`, `cmd/mock-control/algorithms_test.go`.
- Types: `control.AlgorithmProfileCapability{Profile; Algorithms}` (`Algorithms` **embedded**), `ProxyCapabilities.AlgorithmProfiles`, `control.AlgorithmProfileCapabilities()`. The contract test helper `jsonFields` now descends into an embedded struct.
- The rule, written once in `api/README.md` ("Capability advertisement"): take the profile's list; under a floor, intersect key exchanges with that level's declared list; subtract the bans, treating **`curve25519-sha256` and `curve25519-sha256@libssh.org` as one exchange**; refuse an empty axis. `TestTheDeclarationIsEnoughToJudgeEveryBan` proves it matches `Validate` axis for axis, reading decoded JSON only.
- Version: `info.version` **4.7.0**, `policy_version` still **6**. No decision moved, so the register is unchanged. §4.2 gains "As declared (phase 0047)".
- Gotchas: the embedding promotes `Algorithms.Clone`, which returns the lists and drops `profile`, so copy an entry as `ProxyCapabilities.Clone` does. `omitempty` fields plus a `required` contract hold only because no profile has an empty axis, which a test pins. `algorithms` is the union of the profiles' lists because a floor only narrows; profile nesting is not what makes it so.
- **What Control must change** (the sync): re-vendor at 4.7.0 (its copy is 4.1.0). Wire 0014 item 4's seam to `algorithm_profiles` + `algorithm_floors` by the README rule, curve25519 step included, keeping "unknown" only for a missing profile or field. Refuse per proxy and decide refusal vs per-build finding (M17). Never copy the lists. Record per proxy within M5 if the fleet view shows it. Answer `Declares()` for a profiles-only declaration as for a floor-only one. Mark PLAN §5.2 and §10's 0014 dependency met. See "What Control must change" below.

## Details

### Why the entry embeds `Algorithms`, and what that costs

The request sketched a flat entry, `profile` beside the five axis lists, on the
pattern of `AlgorithmFloorCapability`'s `{level, key_exchanges}`. Embedding
`Algorithms` gives exactly that wire shape and keeps the five keys spelled by
the one type that already spells them for `AlgorithmBans` and
`ProxyCapabilities.Algorithms`. `Algorithms`' doc comment now says a list per
axis travels in three places.

The prompt listed three costs, and each got its guard:

- **`required` rests on an invariant.** `Algorithms`' fields are `omitempty`, so
  an empty axis would vanish from the wire while the schema promises it cannot.
  No profile offers an empty axis (0043: `default` is the library's secure set
  on every axis). `TestEveryDeclaredProfileCarriesEveryAxis` marshals every entry
  and requires exactly six keys, each axis a non-empty list.
- **`jsonFields` could not see the axes.** It read only tagged fields, so it saw
  `profile` and skipped the five embedded ones, and the schema test would have
  passed vacuously. It now descends into an anonymous struct field with no JSON
  name, as `encoding/json` does. `TestSpecDocumentsTheAlgorithmSchemas` asserts
  that the type sends exactly six names and that they equal the schema's
  `required`. That assertion is also the check that the descent works. No
  other type `jsonFields` is used on embeds anything, so their results are
  unchanged.
- **The promoted `Clone` is not the entry's.** `ProxyCapabilities.Clone` copies
  each entry as `{Profile: p.Profile, Algorithms: p.Clone()}`, with a comment
  saying that `p.Clone` is the promoted method and copies only the lists. The
  prompt sketched `p.Algorithms.Clone()`, which is the same call, but
  golangci-lint's staticcheck rejects the redundant selector (QF1008) and CI
  runs it. This matters on the wire and not only in a test:
  `internal/routing.Resolver` puts a clone of the build's declaration on every
  authorize request.

A promoted method is also why nothing may add `MarshalJSON` to `Algorithms`: the
entry would marshal as the embedded lists alone, without `profile`. The
six-keys test would catch it.

### The sufficiency test, and what it proves

`internal/control/declaration_test.go` plays Hoplock Control. It marshals this
build's declaration and decodes it into plain maps keyed by the contract's
spelling. The judgement (`wireDeclaration.judge`) shares nothing with the
package's types, so it can pass only if the wire carries enough. The bans are
decoded from JSON the same way, as the server that authored them holds them.
Against it, `validateEmptied` runs the real `AuthorizeResponse.Validate` and
reads which axis it refused on. Any refusal that is not an emptied axis fails
the test, because such a case was built wrongly.

- **Routes:** every profile × floor the contract accepts (`policies()` from
  0045's tests, which excludes `legacy-device` × floor), plus the **absent
  profile** under no floor and each level, because that is the most common route
  shape and the judgement must apply "absent ⇒ `default`".
- **Bans, per axis, generated from what the route really offers:** everything;
  everything but each name, for every name; each name alone; a name no build
  offers (`public_key_auth`'s is `ssh-dss`, which the build offers on another
  axis). On key exchanges, each curve25519 spelling alone, both together, and
  every other exchange plus one spelling. Two multi-axis cases check that the
  two sides report the **first** emptied axis in the same order. That order
  is `key_exchanges`, `ciphers`, `macs`, `host_keys`, `public_key_auth`, which
  is `Validate`'s.
- **Agreement is axis for axis**, not only refuse/accept, so a server's
  message to an author names the axis the proxy would.
- **The matrix must exercise the rule.** The test counts cases where plain set
  subtraction disagrees with `Validate`. It requires at least one such case,
  along with at least one refusal and at least one acceptance. Otherwise a
  shrunken matrix could pass without testing step 3.

Checked in the session by mutation, and reverted. With step 3 dropped from the
judgement, 28 cases fail, each named (for example "default, key_exchanges: every
other exchange plus curve25519-sha256: Validate refuses it on key_exchanges, the
wire judgement accepts the route"). With a build that declares one cipher fewer
than it offers, the "everything but aes256-ctr" cases fail on every profile.
With the schema's `required` cut to two names, or a profile dropped from its
enum, the contract tests fail.

`TestTheJudgementReadsTheDeclarationNotTheBuild` is the cross-build fixture. A
hand-built declaration whose `default` offers one cipher turns a ban on that
cipher from accepted into refused. One whose `default` offers an extra cipher
turns a ban on this build's whole cipher list from refused into accepted. A
declaration that omits a profile is "unknown" (`ok == false`), never a verdict.

### Two things a server author may find surprising

- **Alias-completeness is not what makes the judgement exact. Step 3 is.** The
  declared lists carry both curve25519 spellings, for consistency with
  `algorithm_floors` and because that is what the wire offers. So plain
  subtraction of a ban naming one spelling leaves the other and under-refuses.
  That is exactly the outage the phase exists to prevent. The README states the
  one-exchange rule as a step, with that case, rather than leaving it to
  `AlgorithmBans`' prose.
- **`algorithms` is the union of `algorithm_profiles` because a floor only
  narrows.** The prompt worded this as "the profiles nest". Nesting is what
  made the union equal to `legacy-device`'s entry, which #41 relied on to judge
  `legacy-device` routes. With the per-profile declaration Control no longer
  needs that inference, so the contract states the reason that actually holds,
  and `TestAlgorithmsIsTheUnionOfTheProfiles` pins the union as sets. It fails
  if an expansion ever lets a floor add what no profile offers.

### Beyond the prompt's wording (each deliberate)

- **Pointers without restatements.** `AlgorithmBans`' refusal paragraph in
  `control.yaml` and the README's "Banned algorithms" section each gained one
  sentence naming the two declarations a server judges a ban against. The rule
  itself is written once, in "Capability advertisement", and no prose lists a
  profile's contents.
- The README's "Versioning" section lists what a proxy declares outside
  `policy_version`, the same list as `info.description`, so both name
  `capabilities.algorithm_profiles`. Its absent-value table has a row for the
  field beside its siblings: absent means "unknown", never proof either way.
- `AlgorithmProfiles()`' doc comment names the new builder beside
  `OfferableAlgorithms`, since it is what the declaration is computed over.
- `TestReadmeDocumentsTheContract` now also requires `algorithm_profiles` and
  `curve25519-sha256@libssh.org` in the README.
- **Test names.** The prompt's `TestEnumsMatchContract` is this repository's
  `TestSpecEnumsMatchGoConstants`. `TestEnumsMatchContract` is Control's name
  for its own test. The new row uses `profileNames()`, derived from
  `AlgorithmProfiles()`, beside 0045's `floorNames()`.
- The mock test also posts the same request with the key misspelled and
  expects a `400`. That shows the acceptance comes from a strict decoder that
  knows the field, not from a lax one.

### What was deliberately not done (the prompt's out-of-scope list, held)

No profile is gated on the declaration. `algorithms` is unchanged and still
feeds Control's typo warning. The mock judges no ban against the declaration.
`Validate`, the expansion and `policy_version` are unchanged. No disagreement
between the proxy's refusal and the composition rule was found: the sufficiency
test agrees on every case.

### Cross-repo impact (as written in the PR)

- **`hoplock/enterprise`: None.** It consumes `ext/`, not `api/`. A grep for
  `control\.yaml|algorithm_profile|algorithm_floor|algorithm_bans|ProxyCapabilities|capabilities\.algorithm|OfferableAlgorithms`
  across it hits only its mirrored `docs/CROSS-REPO-PROTOCOL.md` (the
  shared-surfaces table). Its PLAN and 17 queued prompts mention none of the
  algorithm vocabulary.
- **`hoplock/control`:** the obligations below. It is owed a sync even though
  it asked for this (`docs/CROSS-REPO-PROTOCOL.md` §5).

### What Control must change

Checked against `hoplock/control` at `f34e0fd`: the vendored contract is
**4.1.0**, and its 0014 (`0014-northbound-api-and-policy-lifecycle.md`) is still
queued. Its item 4 holds the seam and item 2 the `Declares()` question. Its
PLAN §5.2 and §10's 0014 row record the dependency.

1. **Re-vendor** the contract at `info.version` **4.7.0** (its M1).
   `policy_version` is unchanged at 6. The re-vendor also carries 4.2–4.6, which
   no Control phase has vendored yet.
2. **Wire the seam** named for "each build's offer per profile and per axis" to
   `capabilities.algorithm_profiles`, in 0014 item 4, which already says to do
   so once the declaration has landed and been synced. If 0014 is implemented
   by then, land it in the queued prompt that owns the seam. Use the README's
   rule, the curve25519 step included. "Unknown" then remains only for a proxy
   whose declaration omits the profile, or omits `algorithm_profiles`
   altogether. Judge `legacy-device` from its own entry too, rather than from
   the union inference.
3. **Refuse exactly what the proxy refuses, per proxy.** The declarations are
   per build, so during a rolling upgrade one ban can empty an axis on one
   build and not another. A proxy whose own declaration shows the axis emptied
   refuses that route. Decide under M17 whether the author sees that as a
   refusal or as a per-build finding, and say which. **Never copy the lists
   into code**, which #41 already forbids.
4. **Record** the declaration per proxy within the M5 budget, beside
   `algorithm_floors`, if the fleet view shows per-build offers.
5. **`ProxyCapabilities.Declares()`**: 0014 item 2 asks whether a floor-only
   declaration counts. A profiles-only declaration raises the same question, so
   answer it there, the same way.
6. **Mark the dependency met** in its PLAN §5.2 and §10's 0014 row, citing this
   repository's PR.
