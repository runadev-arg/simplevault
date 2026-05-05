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
];

describe("AAD label parity (FINDING-0026 closure)", () => {
  for (const f of FILES) {
    it(`${f} contains no inline "sv:..v1|" string literal`, () => {
      const src = fs.readFileSync(path.join(cryptoDir, f), "utf8");
      const matches = src.match(/"sv:[^"]+v1\|"/g) ?? [];
      expect(matches).toEqual([]);
    });
  }

  it("aad-labels.ts exports all 6 frozen labels with their pinned values", () => {
    expect(AAD_LABEL_MASTER).toBe("sv:user-master:v1|");
    expect(AAD_LABEL_RECOVERY).toBe("sv:user-recovery:v1|");
    expect(AAD_LABEL_SIGN_SK).toBe("sv:user-sign-sk:v1|");
    expect(AAD_LABEL_KX_SK).toBe("sv:user-kx-sk:v1|");
    expect(AAD_LABEL_TOTP).toBe("sv:user-totp:v1|");
    expect(AAD_LABEL_VAULT_CREDENTIAL).toBe("sv:vault-credential:v1|");
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
