/**
 * EFF Diceware large list — 7776 entries.
 *
 * Source: https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt
 * Upstream raw-file SHA-256 (TAB-delimited):  <PIN-IN-T3>
 * SHA-256 of EFF_LARGE.join("\n") (vendored): <PIN-IN-T3>
 *
 * Vendored to satisfy CSP `connect-src 'self'` + supply-chain pinning
 * (no NPM package — direct upstream copy with integrity hash asserted in
 * `generator.test.ts`).
 *
 * T1 placeholder: a single TBD entry. T3 replaces with the real 7776
 * words and pins both hashes above + in the test.
 */
export const EFF_LARGE: readonly string[] = ["TBD"];
