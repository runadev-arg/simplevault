import { describe, it, expect } from "vitest";

import {
  AAD_LABEL_KX_SK,
  AAD_LABEL_MASTER,
  AAD_LABEL_RECOVERY,
  AAD_LABEL_SIGN_SK,
  AAD_LABEL_TOTP,
  AAD_LABEL_VAULT_CREDENTIAL,
  AAD_LABEL_VAULT_PAGE,
  TITLE_SEARCH_HKDF_INFO,
} from "./aad-labels";

describe("AAD label literals (FROZEN — bumping = data migration)", () => {
  it("byte-equals the canonical strings", () => {
    expect(AAD_LABEL_MASTER).toBe("sv:user-master:v1|");
    expect(AAD_LABEL_RECOVERY).toBe("sv:user-recovery:v1|");
    expect(AAD_LABEL_SIGN_SK).toBe("sv:user-sign-sk:v1|");
    expect(AAD_LABEL_KX_SK).toBe("sv:user-kx-sk:v1|");
    expect(AAD_LABEL_TOTP).toBe("sv:user-totp:v1|");
    expect(AAD_LABEL_VAULT_CREDENTIAL).toBe("sv:vault-credential:v1|");
    expect(AAD_LABEL_VAULT_PAGE).toBe("sv:vault-page:v1|");
    expect(TITLE_SEARCH_HKDF_INFO).toBe("sv:title-search:v1");
  });
});
