/**
 * Phase 04 / Plan 04-10 — Best-effort clipboard clear.
 *
 * Browsers CANNOT truly purge the OS clipboard once the user pastes
 * elsewhere; this overwrite-after-30s is a defence-in-depth stub. We
 * advertise the limitation in inline help text on the editor (REQ-VAULT
 * "copy-with-clear" intent) so users do not assume a stronger guarantee
 * than the platform offers. Phase 12's CSP tightening must NOT block
 * `navigator.clipboard.writeText` (forward-flagged in Plan 04-10 SUMMARY).
 */

const DEFAULT_CLEAR_MS = 30_000;

export async function copyPasswordWithClear(
  pw: string,
  ms: number = DEFAULT_CLEAR_MS,
): Promise<void> {
  if (typeof navigator === "undefined") {
    throw new Error("Clipboard API unavailable");
  }
  // Older / non-secure-context browsers may have `navigator` but not `.clipboard`.
  // The DOM lib type marks `.clipboard` as non-optional, so we reflect-probe.
  const clip: Clipboard | undefined = (navigator as { clipboard?: Clipboard })
    .clipboard;
  if (clip === undefined) {
    throw new Error("Clipboard API unavailable");
  }
  await clip.writeText(pw);
  // Schedule a best-effort overwrite. If the user has already pasted
  // elsewhere, the OS keeps that paste-target's copy; we cannot clear it.
  setTimeout(() => {
    // Swallow rejections (focus-loss / permission revocation) — the
    // schedule is best-effort by design.
    void clip.writeText("").catch(() => {
      /* best-effort */
    });
  }, ms);
}

export const CLIPBOARD_CLEAR_MS = DEFAULT_CLEAR_MS;
