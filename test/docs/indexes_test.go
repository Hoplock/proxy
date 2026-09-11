// Copyright (c) 2026 Mauro Silva. All rights reserved.
// SPDX-License-Identifier: LicenseRef-Proprietary

// Package docs_test holds the durable docs to the invariants they claim.
//
// `docs/PLAN.md` carries three INDEXES — §2's decision register, §5.3's "What
// is true today", and §10's composed renumbering mapping — each of which exists
// so a session can answer a question without reading the body underneath it
// (`docs/PROTOCOL.md` §1). An index is only worth its tokens while it is true,
// and a stale one is worse than none: it will be believed, and the reader has
// by construction chosen not to read the thing that would contradict it.
//
// Keeping them current was a rule a session had to remember, and the phase that
// wrote them proved the rule insufficient twice in one sitting — phase 0031
// landed while that work was open and left D16's register row saying nothing
// had enforced it, and the collision figure in the prose below was first
// obtained by counting a printed list by eye and was wrong. Both are exactly
// what a test catches for free.
//
// It runs in the ordinary `go test ./...` — no Docker, no network — for
// test/topology's reason: the feedback loop for a documentation invariant is
// otherwise a reviewer noticing, or nobody.
package docs_test

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// docsDir is this repo's docs/ directory, relative to this test.
const docsDir = "../../docs"

// repoRoot is this repo's root, relative to this test.
const repoRoot = "../.."

// renumberings is every revision that has moved a queued prompt's number, in
// the order they happened, transcribed from the renumbering notes at the end of
// `docs/PLAN.md` §10.
//
// It is the INPUT the composed mapping in that section is generated from, which
// is what makes the mapping a derived artifact rather than a hand-kept list. A
// renumbering PR adds its revision here and the test tells it what the table
// must then say — which is `docs/PROTOCOL.md` §6's "regenerate it in the same
// PR" expressed as a failing build instead of as an instruction.
//
// `createdHere` names the numbers a revision brought into existence, and it is
// load-bearing rather than decoration: without it the derivation walks a phase's
// history past the point where the phase existed and invents numbers for it.
// That is not hypothetical — it is what the first attempt at this table did.
var renumberings = []struct {
	label       string
	mapping     map[int]int
	createdHere []int
}{
	{"contract-v2", map[int]int{6: 7, 7: 8, 8: 9, 9: 10, 10: 11, 11: 12}, []int{6}},
	{"privileged-access", map[int]int{13: 15, 14: 16}, []int{13, 14, 17, 18}},
	{"fortios-corrections", map[int]int{15: 16, 16: 17, 17: 18, 18: 19, 19: 20, 20: 21, 21: 22, 22: 23, 23: 24, 24: 25, 25: 26}, []int{15}},
	// The two deferred phases were NOT created here: phase 0015's learnings
	// queued multi-VDOM as 0027 and target-enforced expiry as 0028 (at the end
	// of the queue), and this revision moved them to the head. The note's own
	// resolution example says so — "0015's learnings, which queue multi-VDOM as
	// '0027' (now 0016) and target-enforced expiry as '0028' (now 0017)" — so
	// 27→16 and 28→17 belong in the mapping. Recording them as createdHere
	// instead lost both aliases from §10's composed table, which is exactly the
	// failure createdHere exists to prevent, in the other direction.
	{"device-completion", map[int]int{16: 18, 17: 19, 18: 20, 19: 21, 20: 22, 21: 23, 22: 24, 23: 25, 24: 26, 25: 27, 26: 28, 27: 16, 28: 17}, nil},
	{"run-order", map[int]int{31: 22, 32: 23, 25: 24, 22: 25, 23: 26, 24: 27, 26: 28, 27: 29, 28: 30, 30: 31, 33: 32}, nil},
	{"admission-policy", map[int]int{32: 33}, []int{32}},
	{"hop-cred-rejection", map[int]int{33: 34}, []int{33}},
	{"mfa-disclosure", map[int]int{34: 35}, []int{34}},
	{"uid-floor", map[int]int{35: 36}, []int{35}},
	{"access-profile", map[int]int{36: 37}, []int{36}},
}

func readDoc(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(docsDir, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

// section returns the lines of PLAN.md from the heading starting with `start`
// up to (not including) the next heading at `endPrefix`.
func section(t *testing.T, plan, start, endPrefix string) []string {
	t.Helper()
	lines := strings.Split(plan, "\n")
	s := slices.IndexFunc(lines, func(l string) bool { return strings.HasPrefix(l, start) })
	if s < 0 {
		t.Fatalf("docs/PLAN.md: no heading starting %q — if it was renamed, this test and §1's navigation examples both point at the old name", start)
	}
	e := slices.IndexFunc(lines[s+1:], func(l string) bool { return strings.HasPrefix(l, endPrefix) })
	if e < 0 {
		return lines[s:]
	}
	return lines[s : s+1+e]
}

var (
	decisionRe    = regexp.MustCompile(`^- \*\*D(\d+[a-z]?) —`)
	registerRowRe = regexp.MustCompile(`^\| \*\*D(\d+[a-z]?)\*\* \|`)
	phaseRowRe    = regexp.MustCompile(`^\| (\d{4}) \| ([^|]+?)\s*\|`)
	mapRowRe      = regexp.MustCompile(`^\| \*\*(\d{4})\*\*( ⊘)? \| (.*?) \|`)
	layerRe       = regexp.MustCompile(`^\s*\*\*As .*\(phase (\d{4})`)
	fourDigitRe   = regexp.MustCompile(`\d{4}`)
)

// TestDecisionRegisterCoversEveryDecision pins §2's register to §2's decisions.
//
// The register's whole promise is that you can learn which decisions exist, and
// whether each still says what it said, WITHOUT reading the ~8k tokens of
// entries below it. A decision with no row is invisible to every session that
// takes the register at its word; a row for a decision that no longer exists
// sends one looking for an entry that is not there.
func TestDecisionRegisterCoversEveryDecision(t *testing.T) {
	t.Parallel()
	plan := readDoc(t, "PLAN.md")
	lines := section(t, plan, "## 2. Key decisions", "## 3.")

	var decisions, rows []string
	for _, l := range lines {
		if m := decisionRe.FindStringSubmatch(l); m != nil {
			decisions = append(decisions, "D"+m[1])
		}
		if m := registerRowRe.FindStringSubmatch(l); m != nil {
			rows = append(rows, "D"+m[1])
		}
	}

	if len(decisions) == 0 || len(rows) == 0 {
		t.Fatalf("parsed %d decisions and %d register rows in §2; expected both non-zero", len(decisions), len(rows))
	}
	for _, d := range decisions {
		if !slices.Contains(rows, d) {
			t.Errorf("%s has no row in §2's register — add one (what it settles, its status, where it is rendered) or the register is lying by omission", d)
		}
	}
	for _, r := range rows {
		if !slices.Contains(decisions, r) {
			t.Errorf("§2's register has a row for %s but no such decision exists below it", r)
		}
	}
	if !slices.Equal(decisions, rows) && !t.Failed() {
		t.Errorf("§2's register rows are in a different order from the decisions:\n  register:  %v\n  decisions: %v", rows, decisions)
	}
}

// mustStateDecisionRange are the live summaries that tell a reader how many
// decisions the plan carries without opening it. They are asserted to state the
// range at all, not only to state it correctly: a test that checks "any range
// you state must be current" cannot notice the range being DELETED rather than
// updated, and a summary that quietly stops summarising is the same loss to the
// reader as one that lies.
//
// docs/PLAN.md is deliberately not on this list — it is the thing being
// summarised, and today it states no range — but it is still scanned below, so
// a range added to it later has to be current like any other.
var mustStateDecisionRange = []string{"docs/PROTOCOL.md", "README.md"}

// TestDecisionRangeIsCurrent pins the "D1–Dn" range quoted in prose.
//
// Two live files summarise the decisions as a range, and both drifted: they said
// D1–D12 long after D17 existed. A range is a claim about what the plan contains
// and it is worth exactly as much as its last number.
func TestDecisionRangeIsCurrent(t *testing.T) {
	t.Parallel()
	plan := readDoc(t, "PLAN.md")

	highest := 0
	for _, l := range section(t, plan, "## 2. Key decisions", "## 3.") {
		if m := decisionRe.FindStringSubmatch(l); m != nil {
			if n, err := strconv.Atoi(strings.TrimRight(m[1], "abcdefghijklmnopqrstuvwxyz")); err == nil && n > highest {
				highest = n
			}
		}
	}
	if highest == 0 {
		t.Fatal("docs/PLAN.md §2: parsed no decisions, so there is no range to pin")
	}
	want := fmt.Sprintf("D1–D%d", highest)

	rangeRe := regexp.MustCompile(`D1–D(\d+)`)
	stated := map[string]int{}
	for _, f := range []string{"docs/PLAN.md", "docs/PROTOCOL.md", "README.md"} {
		b, err := os.ReadFile(filepath.Join(repoRoot, f))
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for _, m := range rangeRe.FindAllString(string(b), -1) {
			stated[f]++
			if m != want {
				t.Errorf("%s says %q; the plan now carries %s", f, m, want)
			}
		}
	}
	for _, f := range mustStateDecisionRange {
		if stated[f] == 0 {
			t.Errorf("%s no longer states the decision range (%s) — it is one of the live summaries a "+
				"reader uses instead of opening the plan, so dropping the range is a loss to them, not a "+
				"tidy-up. Restate it, or take the file off mustStateDecisionRange and say why", f, want)
		}
	}
}

// phases parses §10's phase table: number -> name, plus which are withdrawn.
//
// It is scoped to §10 rather than run over the whole plan. phaseRowRe matches
// any table row whose first cell is four digits, and the plan is full of
// tables — §9.1's measurements alone carry several. None of them opens with a
// bare four-digit column today, but one that did would become a phantom phase
// that every test here then demands a prompt file for. Scoping costs nothing
// and removes the coupling.
func phases(t *testing.T, plan string) (map[int]string, map[int]bool) {
	t.Helper()
	names, withdrawn := map[int]string{}, map[int]bool{}
	for _, l := range section(t, plan, "## 10. Phased delivery", "## 11.") {
		m := phaseRowRe.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		n, err := strconv.Atoi(m[1])
		if err != nil {
			continue
		}
		names[n] = strings.TrimSpace(m[2])
		if strings.Contains(l, "**Withdrawn") {
			withdrawn[n] = true
		}
	}
	if len(names) == 0 {
		t.Fatal("docs/PLAN.md: parsed no rows from §10's phase table")
	}
	return names, withdrawn
}

// chains derives each current phase's previous numbers by walking the
// renumberings backwards, stopping where the phase was created.
func chains(names map[int]string) map[int][]int {
	out := map[int][]int{}
	for n := range names {
		hist := []int{n}
		created := false
		for i := len(renumberings) - 1; i >= 0 && !created; i-- {
			r := renumberings[i]
			first := hist[0]
			if slices.Contains(r.createdHere, first) {
				created = true
				break
			}
			for old, nw := range r.mapping {
				if nw == first {
					hist = append([]int{old}, hist...)
					break
				}
			}
		}
		out[n] = hist[:len(hist)-1] // drop the current number
	}
	return out
}

// TestComposedMappingMatchesTheRenumberings regenerates §10's mapping.
//
// §6 of the protocol used to ask every reader to compose eleven stacked notes by
// hand. The table exists so nobody does that; this test exists so the table is
// what composing them would have produced.
func TestComposedMappingMatchesTheRenumberings(t *testing.T) {
	t.Parallel()
	plan := readDoc(t, "PLAN.md")
	names, withdrawn := phases(t, plan)
	want := chains(names)

	got := map[int][]int{}
	gotWithdrawn := map[int]bool{}
	// The mapping runs from its heading to the first of the frozen notes, and
	// every note is a blockquote — so "> " is the boundary, not the wording of
	// whichever note happens to be newest. Ending at "> **Queue note" meant a
	// renumbering note added at the top (notes are newest-first, so that is
	// where the next one goes) would silently extend the parsed range over it.
	for _, l := range section(t, plan, "### Resolving a number", "> ") {
		m := mapRowRe.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		n, err := strconv.Atoi(m[1])
		if err != nil {
			continue
		}
		var prev []int
		for _, d := range fourDigitRe.FindAllString(m[3], -1) {
			v, _ := strconv.Atoi(d)
			prev = append(prev, v)
		}
		got[n] = prev
		gotWithdrawn[n] = m[2] != ""
	}

	for n, w := range want {
		if len(w) == 0 && !withdrawn[n] {
			if _, listed := got[n]; listed {
				t.Errorf("§10's mapping lists %04d, which has never been renumbered", n)
			}
			continue
		}
		g, listed := got[n]
		if !listed {
			t.Errorf("§10's mapping is missing %04d (%s); it was previously %v", n, names[n], w)
			continue
		}
		if !slices.Equal(g, w) {
			t.Errorf("§10's mapping has %04d as %v; the renumberings say %v", n, g, w)
		}
		if gotWithdrawn[n] != withdrawn[n] {
			t.Errorf("§10's mapping marks %04d withdrawn=%v; the phase table says %v", n, gotWithdrawn[n], withdrawn[n])
		}
	}
	for n := range got {
		if _, known := want[n]; !known {
			t.Errorf("§10's mapping lists %04d, which is not a phase in the table above it", n)
		}
	}
}

// TestAliasCollisionCountIsCurrent pins the figure the mapping's prose leans on.
//
// "Resolve by subject, not by digits" is only obviously right while the reader
// believes how MANY numbers are ambiguous. That figure was first counted by eye
// off a printed list and was wrong by one, in the very change that introduced
// the table — so it is computed here instead.
func TestAliasCollisionCountIsCurrent(t *testing.T) {
	t.Parallel()
	plan := readDoc(t, "PLAN.md")
	names, _ := phases(t, plan)
	ch := chains(names)

	collisions := 0
	for n := range names {
		for _, prev := range ch {
			if slices.Contains(prev, n) {
				collisions++
				break
			}
		}
	}

	want := fmt.Sprintf("%d of %d", collisions, len(names))
	wantAlt := fmt.Sprintf("%d of the %d", collisions, len(names))
	protocol := readDoc(t, "PROTOCOL.md")
	if !strings.Contains(plan, want) {
		t.Errorf("docs/PLAN.md §10 should say %q (live numbers that are also aliases, of total phases)", want)
	}
	if !strings.Contains(protocol, wantAlt) && !strings.Contains(protocol, want) {
		t.Errorf("docs/PROTOCOL.md §6 should say %q", wantAlt)
	}
}

// TestDeviceSeamHeaderCountsItsLayers pins §5.3's "What is true today" to the
// number of append-only layers it claims to have composed.
//
// The header is read INSTEAD of those layers, so a layer added without
// refreshing it is a phase whose outcome the index silently omits — and the
// reader cannot notice, because not reading the layers is the point.
func TestDeviceSeamHeaderCountsItsLayers(t *testing.T) {
	t.Parallel()
	plan := readDoc(t, "PLAN.md")
	lines := section(t, plan, "### 5.3 ", "## 6.")

	layers := 0
	for _, l := range lines {
		if layerRe.MatchString(l) {
			layers++
		}
	}
	if layers == 0 {
		t.Fatal("docs/PLAN.md §5.3: found no `As <verb> (phase NNNN)` layers")
	}

	words := map[string]int{
		"two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7,
		"eight": 8, "nine": 9, "ten": 10, "eleven": 11, "twelve": 12,
	}
	claimRe := regexp.MustCompile("(\\w+) `As <verb> \\(phase N\\)` blocks")
	m := claimRe.FindStringSubmatch(strings.Join(lines, "\n"))
	if m == nil {
		t.Fatal("docs/PLAN.md §5.3: the current-state header no longer states how many layers it composed")
	}
	claimed, ok := words[strings.ToLower(m[1])]
	if !ok {
		t.Fatalf("docs/PLAN.md §5.3: cannot read %q as a number of layers", m[1])
	}
	if claimed != layers {
		t.Errorf("§5.3's header says it composed %d layers but the section has %d — a new layer means refreshing "+
			"\"What is true today\", not only appending below it", claimed, layers)
	}
}

// TestEveryPhaseHasAPromptOrIsWithdrawn keeps §10's table honest about the
// files it describes.
func TestEveryPhaseHasAPromptOrIsWithdrawn(t *testing.T) {
	t.Parallel()
	names, withdrawn := phases(t, readDoc(t, "PLAN.md"))

	have := map[int]string{}
	for _, dir := range []string{"prompts/queued", "prompts/implemented"} {
		entries, err := os.ReadDir(filepath.Join(repoRoot, dir))
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		for _, e := range entries {
			if n, err := strconv.Atoi(strings.SplitN(e.Name(), "-", 2)[0]); err == nil {
				have[n] = dir
			}
		}
	}

	for n := range names {
		if withdrawn[n] {
			if dir, ok := have[n]; ok {
				t.Errorf("phase %04d is marked withdrawn but %s still holds its prompt — a withdrawal deletes the prompt (§6)", n, dir)
			}
			continue
		}
		if _, ok := have[n]; !ok {
			t.Errorf("phase %04d (%s) is in §10's table but has no prompt in queued/ or implemented/, and is not marked withdrawn", n, names[n])
		}
	}
}

// TestQueuedPromptsNameTheirPlanSections enforces §7's requirement.
//
// §1 has a session NAVIGATE PLAN.md rather than read it, and that saving holds
// only while each prompt says which sections and decisions its phase needs. A
// prompt that names none leaves the next session choosing between reading ~56k
// tokens it mostly does not need and guessing at settled architecture.
func TestQueuedPromptsNameTheirPlanSections(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(repoRoot, "prompts/queued")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}

	ref := regexp.MustCompile(`§\d+(\.\d+)*|\bD\d+[a-z]?\b`)
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".md") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		body := string(b)
		i := strings.Index(body, "## Read first")
		if i < 0 {
			t.Errorf("%s has no \"## Read first\" block (§7)", e.Name())
			continue
		}
		block := body[i:]
		if j := strings.Index(block[len("## Read first"):], "\n## "); j >= 0 {
			block = block[:j+len("## Read first")]
		}
		if !strings.Contains(block, "PLAN.md") || len(ref.FindAllString(block, -1)) == 0 {
			t.Errorf("%s's \"Read first\" names no docs/PLAN.md section (§N) or decision (DN) — §7 requires them "+
				"by number, because §1 navigates the plan rather than reading it", e.Name())
		}
	}
}
