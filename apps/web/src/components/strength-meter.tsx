"use client";

// Plan 04-07 (T1): zxcvbn-ts strength meter, dynamic-imported.
//
// Why dynamic: @zxcvbn-ts/language-en + language-common ship a ~600 KiB
// dictionary. We MUST keep it out of the initial JS bundle of routes that do
// not use the meter (notably /vault list view; see 04-09). Static imports here
// would pull the dictionary into Next.js' shared chunk graph the moment any
// authed page transitively loaded this module. The cached singleton Promise
// below ensures the dictionary is fetched exactly once per session even if
// multiple <StrengthMeter /> instances mount.
import { useEffect, useMemo, useState } from "react";

interface ZxcvbnResult {
  score: number;
  crackTimesDisplay: { offlineFastHashing1e10PerSecond: string };
  feedback: { warning: string; suggestions: string[] };
}

interface ZxcvbnRuntime {
  zxcvbn: (input: string) => ZxcvbnResult;
  loaded: true;
}

let cached: Promise<ZxcvbnRuntime> | null = null;

async function loadZxcvbn(): Promise<ZxcvbnRuntime> {
  if (cached) return cached;
  cached = (async () => {
    // Plan 04-07 truth #2: dynamic imports. Do NOT hoist to top-level.
    const [core, en, common] = await Promise.all([
      import("@zxcvbn-ts/core"),
      import("@zxcvbn-ts/language-en"),
      import("@zxcvbn-ts/language-common"),
    ]);
    core.zxcvbnOptions.setOptions({
      translations: en.translations,
      dictionary: { ...common.dictionary, ...en.dictionary },
      graphs: common.adjacencyGraphs,
    });
    return { zxcvbn: core.zxcvbn as (input: string) => ZxcvbnResult, loaded: true };
  })();
  return cached;
}

export interface StrengthMeterProps {
  password: string;
}

const SCORE_BAR_CLASSES = [
  "bg-red-500",
  "bg-orange-500",
  "bg-yellow-500",
  "bg-lime-500",
  "bg-green-600",
] as const;

export function StrengthMeter({ password }: StrengthMeterProps) {
  const [rt, setRt] = useState<ZxcvbnRuntime | null>(null);
  const [debounced, setDebounced] = useState(password);

  // Kick off lazy dictionary load on mount.
  useEffect(() => {
    let cancelled = false;
    void loadZxcvbn().then((runtime) => {
      if (!cancelled) setRt(runtime);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  // Debounce score recomputation: 200 ms after last keystroke.
  useEffect(() => {
    const t = setTimeout(() => {
      setDebounced(password);
    }, 200);
    return () => {
      clearTimeout(t);
    };
  }, [password]);

  const result = useMemo<ZxcvbnResult | null>(() => {
    if (!rt || debounced === "") return null;
    return rt.zxcvbn(debounced);
  }, [rt, debounced]);

  if (!rt) {
    return (
      <div
        className="h-2 bg-muted animate-pulse"
        aria-label="loading strength meter"
        data-testid="strength-meter-loading"
      />
    );
  }
  if (!result) {
    return (
      <div
        className="h-2 bg-muted"
        aria-label="strength meter"
        data-testid="strength-meter-empty"
      />
    );
  }
  return (
    <div role="status" aria-live="polite" data-testid="strength-meter">
      <div
        className={`h-2 transition-all ${SCORE_BAR_CLASSES[result.score] ?? "bg-muted"}`}
        style={{ width: `${String((result.score + 1) * 20)}%` }}
        data-score={result.score}
      />
      <p className="text-xs mt-1">
        Crack time: {result.crackTimesDisplay.offlineFastHashing1e10PerSecond}
      </p>
      {result.feedback.warning && (
        <p className="text-xs text-orange-600">{result.feedback.warning}</p>
      )}
      {result.feedback.suggestions.length > 0 && (
        <ul className="text-xs text-muted-foreground">
          {result.feedback.suggestions.map((s, i) => (
            <li key={i}>• {s}</li>
          ))}
        </ul>
      )}
    </div>
  );
}
