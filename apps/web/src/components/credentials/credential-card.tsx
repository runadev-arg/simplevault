"use client";

/**
 * Phase 04 / Plan 04-09 — per-credential card.
 *
 * RESPONSIBILITIES (LOAD-BEARING):
 *   1. Render a placeholder skeleton until the card scrolls into view.
 *   2. On first intersection, fetch the encrypted blob via
 *      `getCredential(id)` (Plan 04-06), build the AAD via
 *      `buildVaultCredentialAad` (Plan 04-04), decrypt under master_DEK
 *      (in-memory keyStore), Zod-parse via `DecryptedCredentialSchema`
 *      (Plan 04-10 shape), and surface a SUMMARY ONLY (name, primary
 *      URL, username, is_favorite, updated_at) to the parent.
 *   3. Hand the SHA-256 hash of the password (NOT the plaintext) to the
 *      parent's reuse-Map lookup. The plaintext never leaves this
 *      component's local-scope after the hash is computed; React state
 *      holds only the summary.
 *   4. Show `<ReuseBadge>` when `reuseMap` reports >= 1 collision.
 *
 * INVARIANT: the password plaintext is NEVER rendered to the DOM here.
 * Reveal lives only on `/credential/[id]` (Plan 04-10).
 */

import { ready } from "@simplevault/crypto/browser";
import type { JSX } from "react";
import { useEffect, useRef, useState } from "react";

import {
  getCredential,
  type CredentialResponse,
} from "../../lib/api/credentials-client";
import { keyStore } from "../../lib/auth/key-store";
import {
  buildVaultCredentialAad,
  decryptCredential,
} from "../../lib/crypto/credential-cipher";
import { DecryptedCredentialSchema } from "../../lib/vault/credential-shape";
import {
  passwordHash,
  reuseCountForCred,
} from "../../lib/vault/reuse-set";
import {
  Card,
  CardDescription,
  CardHoverItem,
  CardTitle,
} from "../aceternity/cards/card-grid";

import { ReuseBadge } from "./reuse-badge";

export interface CredentialSummaryView {
  id: string;
  name: string;
  primaryUrl: string;
  username: string;
  pwHash: string;
  isFavorite: boolean;
  updatedAt: string;
}

export interface CredentialCardProps {
  summary: { id: string; version: number; updatedAt: string };
  vaultId: string;
  email: string;
  accessToken: string;
  reuseMap: Map<string, string[]>;
  onDecrypted: (view: CredentialSummaryView) => void;
  /** Phase 07 — shared vault DEK. When provided, used instead of master_dek. */
  dek?: Uint8Array;
}

export function CredentialCard({
  summary,
  vaultId,
  email,
  accessToken,
  reuseMap,
  onDecrypted,
  dek,
}: CredentialCardProps): JSX.Element {
  const ref = useRef<HTMLDivElement>(null);
  const [view, setView] = useState<CredentialSummaryView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const decryptedRef = useRef(false);

  useEffect(() => {
    const node = ref.current;
    if (node === null) return undefined;
    if (decryptedRef.current) return undefined;
    const obs = new IntersectionObserver((entries) => {
      const entry = entries[0];
      if (entry?.isIntersecting !== true) return;
      if (decryptedRef.current) return;
      decryptedRef.current = true;
      obs.disconnect();
      void doDecrypt();
    }, { rootMargin: "50px" });
    obs.observe(node);
    return () => {
      obs.disconnect();
    };
    async function doDecrypt(): Promise<void> {
      try {
        await ready();
        const masterDek = dek ?? keyStore.getBytes("master_dek");
        if (masterDek === undefined) {
          throw new Error("Vault locked — master_DEK missing from keyStore");
        }
        const blob: CredentialResponse = await getCredential(
          accessToken,
          summary.id,
        );
        const aad = buildVaultCredentialAad({
          vaultId,
          credentialId: summary.id,
          version: blob.version,
          email,
        });
        const json = await decryptCredential(
          { ciphertext: blob.ciphertext, nonce: blob.nonce },
          masterDek,
          aad,
        );
        const parsed = DecryptedCredentialSchema.parse(JSON.parse(json));
        const v: CredentialSummaryView = {
          id: summary.id,
          name: parsed.name,
          primaryUrl: parsed.urls[0] ?? "",
          username: parsed.username,
          // Hash the password right here, then drop the plaintext. Only
          // the 64-char hex hash escapes via React state.
          pwHash: passwordHash(parsed.password),
          isFavorite: parsed.is_favorite,
          updatedAt: blob.updatedAt,
        };
        setView(v);
        onDecrypted(v);
      } catch (e) {
        setError(e instanceof Error ? e.message : "Decrypt failed");
      }
    }
  }, [summary.id, vaultId, email, accessToken, onDecrypted, dek]);

  const reuseCount =
    view !== null ? reuseCountForCred(reuseMap, view.id, view.pwHash) : 0;

  return (
    <CardHoverItem>
      <Card>
        <div ref={ref} className="flex h-full flex-col">
          {error !== null ? (
            <p className="text-sm text-red-300" role="alert">
              {error}
            </p>
          ) : view === null ? (
            <div className="animate-pulse space-y-2" aria-busy="true">
              <div className="h-4 w-3/4 rounded bg-zinc-800" />
              <div className="h-3 w-1/2 rounded bg-zinc-800" />
              <div className="h-3 w-1/3 rounded bg-zinc-800" />
            </div>
          ) : (
            <>
              <div className="flex items-start justify-between gap-2">
                <CardTitle>{view.name}</CardTitle>
                {view.isFavorite ? (
                  <span
                    aria-label="Favourite"
                    title="Favourite"
                    className="text-yellow-400"
                  >
                    ★
                  </span>
                ) : null}
              </div>
              {view.primaryUrl !== "" ? (
                <CardDescription>{view.primaryUrl}</CardDescription>
              ) : null}
              {view.username !== "" ? (
                <p className="mt-1 truncate text-xs text-zinc-500">
                  {view.username}
                </p>
              ) : null}
              <div className="mt-3 flex items-center gap-2">
                <ReuseBadge count={reuseCount} />
              </div>
            </>
          )}
        </div>
      </Card>
    </CardHoverItem>
  );
}
