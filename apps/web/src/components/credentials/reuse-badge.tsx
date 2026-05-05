/**
 * Phase 04 / Plan 04-09 — `<ReuseBadge>` shared component.
 *
 * Cross-plan handoff: Plan 04-10's credential-detail / edit views import
 * THIS file (per Plan 04-09 SUMMARY) so the badge styling + a11y wording
 * stay consistent across the list view (`/vault`) and the edit view
 * (`/credential/[id]`).
 *
 * Informational only — never blocks save (Phase 04 INDEX Truth 8). The
 * input `count` is the number of OTHER credentials sharing the password
 * (self-excluded), so `count <= 0` renders nothing.
 */

import type { JSX } from "react";

export interface ReuseBadgeProps {
  count: number;
  className?: string;
}

export function ReuseBadge({ count, className = "" }: ReuseBadgeProps): JSX.Element | null {
  if (count <= 0) return null;
  const label =
    count === 1
      ? "Password reused in 1 other credential"
      : `Password reused in ${String(count)} other credentials`;
  return (
    <span
      role="status"
      aria-label={label}
      title={label}
      className={`inline-flex items-center gap-1 rounded-md border border-orange-500/40 bg-orange-500/10 px-2 py-0.5 text-xs font-medium text-orange-300 ${className}`}
    >
      <span aria-hidden>↻</span>
      <span>{String(count)}</span>
    </span>
  );
}
