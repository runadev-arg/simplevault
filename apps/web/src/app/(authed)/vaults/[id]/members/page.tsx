"use client";

/**
 * Phase 07 / Plan 07-05 — `/vaults/[id]/members`
 *
 * Member list for a shared vault. Owners can remove other members; any member
 * can leave the vault. Leaving wipes the vault DEK from keyStore.
 */

import { type JSX, useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";

import { me as apiMe } from "../../../../../lib/api/auth-client";
import { useAuth } from "../../../../../lib/auth/auth-context";
import { keyStore } from "../../../../../lib/auth/key-store";
import {
  type MemberSummary,
  listMembers,
  removeMember,
} from "../../../../../lib/api/vault-sharing-client";

export default function MembersPage(): JSX.Element {
  const { accessToken } = useAuth();
  const params = useParams<{ id: string }>();
  const vaultId = params.id;
  const router = useRouter();

  const [members, setMembers] = useState<MemberSummary[] | null>(null);
  const [currentUserId, setCurrentUserId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [confirm, setConfirm] = useState<{ userId: string; email: string; isSelf: boolean } | null>(null);
  const [processing, setProcessing] = useState(false);

  useEffect(() => {
    if (accessToken === null) return undefined;
    const flag = { cancelled: false };
    void (async (): Promise<void> => {
      try {
        const [meRes, memberList] = await Promise.all([
          apiMe(accessToken),
          listMembers(accessToken, vaultId),
        ]);
        if (flag.cancelled) return;
        setCurrentUserId(meRes.id);
        setMembers(memberList);
      } catch (e) {
        if (flag.cancelled) return;
        setError(e instanceof Error ? e.message : "Failed to load members");
      }
    })();
    return () => {
      flag.cancelled = true;
    };
  }, [accessToken, vaultId]);

  // Determine if the current user is an owner.
  const currentUserRole =
    members !== null && currentUserId !== null
      ? (members.find((m) => m.userId === currentUserId)?.role ?? null)
      : null;
  const isOwner = currentUserRole === "owner";

  async function handleConfirmedAction(): Promise<void> {
    if (confirm === null || accessToken === null) return;
    setProcessing(true);
    try {
      await removeMember(accessToken, vaultId, confirm.userId);
      if (confirm.isSelf) {
        // Leaving: wipe vault DEK and redirect away.
        keyStore.delete("vault_dek:" + vaultId);
        router.replace("/vaults");
      } else {
        // Removing other: refresh member list.
        const updated = await listMembers(accessToken, vaultId);
        setMembers(updated);
        setConfirm(null);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Action failed.");
      setConfirm(null);
    } finally {
      setProcessing(false);
    }
  }

  function formatDate(iso: string): string {
    try {
      return new Date(iso).toLocaleDateString(undefined, {
        year: "numeric",
        month: "short",
        day: "numeric",
      });
    } catch {
      return iso;
    }
  }

  if (accessToken === null) {
    return (
      <main className="flex min-h-screen items-center justify-center">
        <p className="text-zinc-400">Loading…</p>
      </main>
    );
  }

  if (error !== null) {
    return (
      <main className="mx-auto max-w-3xl px-6 py-10">
        <p
          role="alert"
          className="rounded-md border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-200"
        >
          {error}
        </p>
        <div className="mt-4">
          <a
            href={`/vaults/${encodeURIComponent(vaultId)}`}
            className="text-sm text-zinc-400 hover:text-zinc-200"
          >
            ← Back to vault
          </a>
        </div>
      </main>
    );
  }

  if (members === null || currentUserId === null) {
    return (
      <main className="mx-auto max-w-3xl px-6 py-10">
        <p className="text-zinc-400">Loading members…</p>
      </main>
    );
  }

  return (
    <main className="mx-auto max-w-3xl px-6 py-10">
      <h1 className="mb-6 text-2xl font-semibold tracking-tight">Vault Members</h1>

      {/* Confirm dialog */}
      {confirm !== null && (
        <div
          role="dialog"
          aria-modal="true"
          className="mb-6 rounded-lg border border-zinc-700 bg-zinc-900 px-5 py-4"
        >
          <p className="mb-4 text-sm text-zinc-100">
            {confirm.isSelf
              ? "Leave this vault? You will lose access."
              : `Remove ${confirm.email} from this vault?`}
          </p>
          <div className="flex gap-3">
            <button
              type="button"
              disabled={processing}
              onClick={() => void handleConfirmedAction()}
              className="rounded-md bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-500 disabled:opacity-50"
            >
              {processing ? "Processing…" : "Confirm"}
            </button>
            <button
              type="button"
              disabled={processing}
              onClick={() => {
                setConfirm(null);
              }}
              className="rounded-md border border-zinc-700 px-4 py-2 text-sm font-medium text-zinc-300 hover:bg-zinc-800 disabled:opacity-50"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-zinc-800 text-left text-zinc-400">
              <th className="pb-3 pr-4 font-medium">Email</th>
              <th className="pb-3 pr-4 font-medium">Role</th>
              <th className="pb-3 pr-4 font-medium">Joined</th>
              <th className="pb-3 font-medium">Action</th>
            </tr>
          </thead>
          <tbody>
            {members.map((member) => {
              const isSelf = member.userId === currentUserId;
              const canRemove = !isSelf && isOwner && member.role !== "owner";
              return (
                <tr key={member.userId} className="border-b border-zinc-800/50">
                  <td className="py-3 pr-4 text-zinc-100">
                    {member.email}
                    {isSelf && (
                      <span className="ml-2 text-xs text-zinc-500">(you)</span>
                    )}
                  </td>
                  <td className="py-3 pr-4 capitalize text-zinc-300">{member.role}</td>
                  <td className="py-3 pr-4 text-zinc-400">{formatDate(member.joinedAt)}</td>
                  <td className="py-3">
                    {isSelf && member.role !== "owner" && (
                      <button
                        type="button"
                        onClick={() => {
                          setConfirm({ userId: member.userId, email: member.email, isSelf: true });
                        }}
                        className="rounded-md border border-zinc-700 px-3 py-1.5 text-xs font-medium text-zinc-300 hover:bg-zinc-800"
                      >
                        Leave vault
                      </button>
                    )}
                    {canRemove && (
                      <button
                        type="button"
                        onClick={() => {
                          setConfirm({ userId: member.userId, email: member.email, isSelf: false });
                        }}
                        className="rounded-md border border-red-700/50 px-3 py-1.5 text-xs font-medium text-red-300 hover:bg-red-900/30"
                      >
                        Remove
                      </button>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <div className="mt-6">
        <a
          href={`/vaults/${encodeURIComponent(vaultId)}`}
          className="text-sm text-zinc-400 hover:text-zinc-200"
        >
          ← Back to vault
        </a>
      </div>
    </main>
  );
}
