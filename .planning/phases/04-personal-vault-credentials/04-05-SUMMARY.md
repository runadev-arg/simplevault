# Plan 04-05 — Password generator + EFF-large wordlist + entropy bounds (SUMMARY)

## Outcome

Wave 2 / Plan 05 closed. Three task commits + one test-data follow-up + this docs commit:

- `017b26c` test(04-05-T1): generator entropy + class-invariant + EFF integrity (RED) — landed before this session.
- `cb09cda` feat(04-05-T2): GREEN generatePassword + generatePassphrase (rejection sampling).
- `5937308` feat(04-05-T3): vendor EFF large wordlist (7776 entries) + SHA-256 pin.
- `5e86cd4` test(04-05-T3): handle EFF hyphenated words in passphrase split test.

Final test count: 14/14 green in `apps/web/src/lib/passwords/generator.test.ts`
(RED skeleton was 13 tests; T3 follow-up split the passphrase test into a strict
whitespace-separator invariant + a softer default-`-` smoke).

## Files

- `apps/web/src/lib/passwords/generator.ts` — `generatePassword` + `generatePassphrase`.
- `apps/web/src/lib/passwords/eff-large.ts` — 7776-entry vendored EFF Diceware large list.
- `apps/web/src/lib/passwords/generator.test.ts` — 14 invariant tests (entropy, class
  guarantee, length/word bounds, uniqueness, `Math.random`-clean, EFF integrity).

## Design choices

### Entropy source

`crypto.getRandomValues` (sync global; available in Node 20+ and browsers).
The plan's stated preference for `libsodium randombytes_uniform` would have
required either a top-level `await sodium.ready` (incompatible with the
sync test surface) or making `generatePassword` async (incompatible with
the 1000-trial sync invariant). The web-cryptography `getRandomValues`
primitive is itself a Web Crypto / Node `crypto` standard with the same
underlying CSPRNG guarantees, and the plan's reference implementation in
`<task>` Task 2 uses `crypto.getRandomValues` directly. **Deviation**
relative to the user-prompt phrasing of "libsodium via existing
`apps/web/src/lib/crypto/sodium.ts` wrapper": that wrapper does not exist
in the codebase (verified — only `aad-labels.ts`, `*-derivations.ts`,
`secret-key-format.ts`, `totp-wrap.ts`), and existing call-sites import
`libsodium-wrappers-sumo` directly (e.g. `signup-derivations.ts:135`).
The plan's reference code uses `crypto.getRandomValues`, which is what we
implemented. The grep-clean invariant for `Math.random` is asserted in
the test.

### Rejection sampling (no modulo bias)

`randInt(maxExclusive)` reads one byte from `Uint8Array(1)` and rejects
values ≥ `256 - (256 % maxExclusive)`. `randIndex16(maxExclusive)` does
the same with a `Uint16Array(1)` sample for the 7776-entry wordlist
(7776 < 65536). Naive `byte % maxExclusive` would bias toward the
low-residue values for any `maxExclusive` not dividing 256 (or 65536);
rejection eliminates this.

### Class guarantee + Fisher–Yates

`generatePassword` first picks one character from each enabled class
(guaranteeing the regex assertion), fills the remainder from the union
charset, then Fisher–Yates shuffles using `randInt(i+1)` so the
guaranteed chars aren't always at the front.

### SYMBOLS charset (25 chars vs the spec's "≈32")

`SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>/?"` is 25 characters. Total
all-classes charset = 26+26+10+25 = **87**. Default (length=20)
entropy = `20 × log2(87) ≈ 128.85 bits` — above the 128-bit anchor in
REQ-VAULT-003. Operator can extend `SYMBOLS` later (e.g. add `~` `` ` ``
`'` `"` `\` `|`) to reach 32+ if a higher anchor is desired; the empirical
entropy test expects ≥ 128 bits, leaving headroom.

### Defaults rationale

- `generatePassword`: `length=20`, all four classes on. 20 × log2(87) ≈ 128.85 bits.
- `generatePassphrase`: `wordCount=5`, `separator="-"`. 5 × log2(7776) ≈ 64.6 bits — fine
  for memorable passphrases used as credential subfields, not as Master Password (the
  Master Password is salt + Argon2id-derived per Phase 02).

## EFF wordlist vendoring

### Provenance + integrity

- Source: <https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt>
- Upstream raw-file SHA-256 (TAB-delimited):
  `addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e`
- Vendored array-form SHA-256 (`EFF_LARGE.join("\n") + "\n"`):
  `6d557f0693958fb5e650b68b5bee585eb82cf4da32965505c789e924743bc522`

The array-form hash is asserted at runtime in `generator.test.ts`; CI
will fail if the array drifts.

### Re-vendoring procedure

Documented in the `eff-large.ts` header. One-shot script used to generate
the file in T3:

```bash
curl -fsS https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt -o /tmp/eff_large.txt
shasum -a 256 /tmp/eff_large.txt   # expect addd3553...
awk -F$'\t' '{print $2}' /tmp/eff_large.txt > /tmp/eff_words.txt
wc -l /tmp/eff_words.txt           # expect 7776
node -e '
  const fs=require("fs"), crypto=require("crypto");
  const words = fs.readFileSync("/tmp/eff_words.txt","utf8").trim().split("\n");
  const h = crypto.createHash("sha256").update(words.join("\n")+"\n","utf8").digest("hex");
  console.log("array-form sha256:", h);
'
```

Then regenerate `eff-large.ts` (the loop body is a `JSON.stringify` per
word + comma per line) and update `EXPECTED_EFF_JOIN_HASH` in
`generator.test.ts` if the upstream file ever changes.

### Hyphenated-word footnote

The EFF list contains 4 entries with `-`: `drop-down`, `felt-tip`,
`t-shirt`, `yo-yo`. With the operator default `separator="-"` this means
`split("-").length` can exceed `wordCount`. The strict membership invariant
is therefore exercised with `separator=" "` (whitespace cannot occur in
any EFF word). The default `-` separator is still covered by a softer
"non-empty + ≥ wordCount−1 dashes" smoke. Plan 04-12 Cypress spec should
mirror this split.

## Cross-plan handoffs

- Plan 04-10 (credential editor): `import { generatePassword, generatePassphrase } from "@/lib/passwords/generator"`.
- Plan 04-12 (Cypress password-generator spec): runs the 1000-trial
  in-bounds + uniqueness assertions in the browser for parity.

## Verification matrix (all 5 truths TRUE)

| # | Truth | Evidence |
|---|-------|----------|
| 1 | Generator API + length/words bounds | `generator.ts` lines 18–28, 75–110, 113–127 |
| 2 | `crypto.getRandomValues` only — `Math.random` grep clean | `Math.random clean` test passes |
| 3 | EFF list 7776 entries + SHA-256 pinned | `eff-large.ts` (7776 entries); test asserts hash |
| 4 | Default-output entropy bounds | empirical Shannon ≥ 128 bits (10000 trials) |
| 5 | TDD coverage (a)–(g) | 14/14 tests green |

## Deviations

1. **`libsodium` wrapper vs `crypto.getRandomValues`** — the user-prompt
   referenced an `apps/web/src/lib/crypto/sodium.ts` wrapper that does
   not exist; the plan's own reference code uses `crypto.getRandomValues`
   directly, so we followed the plan. CSPRNG guarantees are equivalent.
2. **Test 7 split into two tests** — the original RED test asserted
   `split('-').length === wordCount`, which contradicts the EFF list's
   4 hyphenated entries. Split into a strict whitespace-separator
   invariant + a softer default-`-` smoke (committed as `5e86cd4`).
   Total tests: 14 (was 13 in RED).
3. **No `apps/web` build verification** — sibling Wave-2 plans 04-02 /
   04-03 / 04-04 have in-flight TS/ESLint errors in unrelated files
   (`credential-cipher.ts`, `signup-derivations.ts` import-order, etc.)
   that block `pnpm --filter @simplevault/web build`. Verified locally
   that **only** generator.ts + eff-large.ts + generator.test.ts pass
   their own type-check and lint (TS strict + non-null/non-nullable
   rule pair). Sibling plans will green up the build when their own
   T2/T3s land.
