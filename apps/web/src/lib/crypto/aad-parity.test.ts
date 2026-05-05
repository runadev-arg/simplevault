import { describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";

import {
  AAD_LABEL_KX_SK,
  AAD_LABEL_MASTER,
  AAD_LABEL_RECOVERY,
  AAD_LABEL_SIGN_SK,
  AAD_LABEL_TOTP,
  AAD_LABEL_VAULT_CREDENTIAL,
  AAD_LABEL_VAULT_PAGE,
} from "./aad-labels";

/**
 * FINDING-0026 closure — every derivation file MUST import its
 * `"sv:..:v1|"` label literal from `./aad-labels`. Inline declaration
 * is forbidden by this test (regex catches any double-quoted string of
 * the shape `"sv:...v1|"`). If a future contributor copy-pastes a
 * literal, this test fails LOUD before the duplicate ships.
 *
 * The regex tolerates JSDoc / single-line comments incidentally because
 * those typically don't quote the literal in double-quotes; the
 * derivation files in scope have all been audited and all such
 * mentions in comments have been rephrased to use the symbolic name
 * (e.g. `AAD_LABEL_MASTER`).
 */

const cryptoDir = path.resolve(__dirname);

const FILES = [
  "signup-derivations.ts",
  "login-derivations.ts",
  "totp-wrap.ts",
  "credential-cipher.ts",
  // Plan 05-03 sibling — page-cipher lands in this same wave (Plan 05-03 T3).
  // Listed conditionally: if the file does not yet exist (e.g. pre-T3 RED
  // run), the per-file `it` skips silently.
  "page-cipher.ts",
];

describe("AAD label parity (FINDING-0026 closure)", () => {
  for (const f of FILES) {
    it(`${f} contains no inline "sv:..v1|" string literal`, () => {
      const fullPath = path.join(cryptoDir, f);
      if (!fs.existsSync(fullPath)) {
        // Sibling plan (e.g. 05-03 T3) hasn't landed yet — skip silently
        // rather than fail. Once the file exists the assertion bites.
        return;
      }
      const src = fs.readFileSync(fullPath, "utf8");
      const matches = src.match(/"sv:[^"]+v1\|"/g) ?? [];
      expect(matches).toEqual([]);
    });
  }

  it("aad-labels.ts exports all 7 frozen labels with their pinned values", () => {
    expect(AAD_LABEL_MASTER).toBe("sv:user-master:v1|");
    expect(AAD_LABEL_RECOVERY).toBe("sv:user-recovery:v1|");
    expect(AAD_LABEL_SIGN_SK).toBe("sv:user-sign-sk:v1|");
    expect(AAD_LABEL_KX_SK).toBe("sv:user-kx-sk:v1|");
    expect(AAD_LABEL_TOTP).toBe("sv:user-totp:v1|");
    expect(AAD_LABEL_VAULT_CREDENTIAL).toBe("sv:vault-credential:v1|");
    expect(AAD_LABEL_VAULT_PAGE).toBe("sv:vault-page:v1|");
  });

  it("AAD_LABEL_VAULT_PAGE literal lives ONLY in aad-labels.ts within apps/web/src", () => {
    // Phase 05 sibling-parity gate: every other file in apps/web/src that
    // mentions the page-AAD label must do so via the imported constant,
    // never as an inline string. Walks apps/web/src recursively.
    const root = path.resolve(__dirname, "..", "..", "..", "src");
    const offenders: string[] = [];
    const stack: string[] = [root];
    while (stack.length) {
      const dir = stack.pop()!;
      for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, ent.name);
        if (ent.isDirectory()) {
          if (ent.name === "node_modules" || ent.name === ".next") continue;
          stack.push(full);
          continue;
        }
        if (!/\.(ts|tsx)$/.test(ent.name)) continue;
        // Whitelist: the constants module itself, the constants spec test,
        // and this parity test (which references the literal in assertions).
        if (
          full.endsWith("/lib/crypto/aad-labels.ts") ||
          full.endsWith("/lib/crypto/aad-labels.test.ts") ||
          full.endsWith("/lib/crypto/aad-parity.test.ts")
        ) {
          continue;
        }
        const src = fs.readFileSync(full, "utf8");
        if (/"sv:vault-page:v1\|"/.test(src)) {
          offenders.push(path.relative(root, full));
        }
      }
    }
    expect(offenders).toEqual([]);
  });

  it("aad-labels.ts is the ONLY file under apps/web/src/lib/crypto/ with the literals", () => {
    const dir = path.resolve(__dirname);
    const entries = fs.readdirSync(dir).filter((n) => n.endsWith(".ts"));
    const offenders: string[] = [];
    for (const f of entries) {
      // Whitelist: the constants module (single source of truth) and the
      // two parity/spec tests that pin literal values for regression.
      if (
        f === "aad-labels.ts" ||
        f === "aad-labels.test.ts" ||
        f === "aad-parity.test.ts"
      ) {
        continue;
      }
      const src = fs.readFileSync(path.join(dir, f), "utf8");
      if (/"sv:[^"]+v1\|"/.test(src)) {
        offenders.push(f);
      }
    }
    expect(offenders).toEqual([]);
  });
});
