// Source: https://ui.aceternity.com/components/card-hover-effect
// Vendored on: 2026-05-04
// Upstream commit/version: aceternity-ui copy-paste docs as of 2026-05-04
// License: MIT (per Aceternity docs)
//
// Adaptation note (Plan 04-09): the upstream snippet pulls in `framer-motion`
// for an animated hover-glow. SimpleVault honours a 250 KiB initial-JS budget
// (see `apps/web/scripts/bundle-budget.mjs`) and is not allowed to runtime-fetch
// the Aceternity component. To stay under-budget we vendor the layout
// primitives VERBATIM and replace the framer-motion `<motion.span>` glow with
// a CSS-only sibling using Tailwind transitions. No CDN, no `aceternity-ui`
// NPM dep.
"use client";

import type { JSX, ReactNode } from "react";
import { useState } from "react";

/**
 * <CardGrid> — top-level layout primitive. Maps to the upstream
 * `HoverEffect` outer wrapper. Children are the per-item cards (we feed it
 * `<CredentialCard>` from `apps/web/src/components/credentials/credential-card.tsx`).
 *
 * Mobile-first: the grid template lives in the className the caller passes,
 * so the consumer (vault page) can tune the breakpoints. The default is
 * `grid-cols-1 md:grid-cols-2 lg:grid-cols-3` per Plan 04-09.
 */
export function CardGrid({
  children,
  className = "",
}: {
  children: ReactNode;
  className?: string;
}): JSX.Element {
  const cls =
    className.length > 0
      ? className
      : "grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4";
  return <div className={cls}>{children}</div>;
}

/**
 * <CardHoverItem> — per-card outer wrapper that renders the Aceternity
 * hover-glow behind its child via a sibling absolutely-positioned span.
 * The glow is opacity-0 by default, opacity-100 when the parent is hovered
 * or focus-within. Pure CSS — no animation runtime cost.
 */
export function CardHoverItem({
  children,
  className = "",
  onMouseEnter,
  onFocus,
}: {
  children: ReactNode;
  className?: string;
  onMouseEnter?: () => void;
  onFocus?: () => void;
}): JSX.Element {
  const [hovered, setHovered] = useState(false);
  return (
    <div
      className={`group relative block h-full w-full ${className}`}
      onMouseEnter={() => {
        setHovered(true);
        onMouseEnter?.();
      }}
      onMouseLeave={() => {
        setHovered(false);
      }}
      onFocus={() => {
        setHovered(true);
        onFocus?.();
      }}
      onBlur={() => {
        setHovered(false);
      }}
    >
      <span
        aria-hidden
        className={`absolute inset-0 block h-full w-full rounded-2xl bg-zinc-800/60 transition-opacity duration-300 ${
          hovered ? "opacity-100" : "opacity-0"
        }`}
      />
      <div className="relative z-10 h-full w-full">{children}</div>
    </div>
  );
}

/**
 * <Card> — the card chrome the upstream snippet ships. Border + padding +
 * dark-mode-friendly defaults. Caller composes the body.
 */
export function Card({
  children,
  className = "",
}: {
  children: ReactNode;
  className?: string;
}): JSX.Element {
  return (
    <div
      className={`relative h-full w-full overflow-hidden rounded-2xl border border-zinc-800 bg-zinc-900/50 p-4 ${className}`}
    >
      {children}
    </div>
  );
}

export function CardTitle({
  children,
  className = "",
}: {
  children: ReactNode;
  className?: string;
}): JSX.Element {
  return (
    <h3 className={`mt-2 font-semibold tracking-tight text-zinc-100 ${className}`}>
      {children}
    </h3>
  );
}

export function CardDescription({
  children,
  className = "",
}: {
  children: ReactNode;
  className?: string;
}): JSX.Element {
  return (
    <p
      className={`mt-1 truncate text-sm text-zinc-400 ${className}`}
      title={typeof children === "string" ? children : undefined}
    >
      {children}
    </p>
  );
}
