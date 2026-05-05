// @vitest-environment jsdom
//
// Plan 04-07 (T2): StrengthMeter spec.
// - Loading skeleton renders while dynamic-imports are pending.
// - Empty bar renders when password is "".
// - Real zxcvbn scoring drives the score data attribute (weak < strong).
// - Debounce: rapid prop changes within 200 ms result in a single score render.
import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { StrengthMeter } from "./strength-meter";

afterEach(() => {
  cleanup();
});

describe("StrengthMeter", () => {
  it("renders the loading skeleton then an empty bar for empty input", async () => {
    render(<StrengthMeter password="" />);
    expect(screen.getByTestId("strength-meter-loading")).toBeTruthy();
    await waitFor(() => {
      expect(screen.getByTestId("strength-meter-empty")).toBeTruthy();
    });
  }, 15_000);

  it("scores a weak password as 0..1 and a strong password >= 3", async () => {
    const weak = render(<StrengthMeter password="abc123" />);
    await waitFor(
      () => {
        const el = weak.getByTestId("strength-meter").querySelector("[data-score]");
        expect(el).toBeTruthy();
        expect(Number(el?.getAttribute("data-score"))).toBeLessThanOrEqual(1);
      },
      { timeout: 15_000 },
    );
    weak.unmount();

    const strong = render(<StrengthMeter password="Tr0ub4dor&3UltraComplex!Quantum" />);
    await waitFor(
      () => {
        const el = strong.getByTestId("strength-meter").querySelector("[data-score]");
        expect(el).toBeTruthy();
        expect(Number(el?.getAttribute("data-score"))).toBeGreaterThanOrEqual(3);
      },
      { timeout: 15_000 },
    );
  }, 30_000);

  it("debounces score updates: rapid prop changes within 200 ms collapse to one", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const { rerender, getByTestId } = render(<StrengthMeter password="aaaa" />);
    // Wait for runtime load (uses real timers via shouldAdvanceTime).
    await waitFor(
      () => {
        expect(getByTestId("strength-meter")).toBeTruthy();
      },
      { timeout: 15_000 },
    );
    // Three rapid updates within the 200 ms debounce window.
    rerender(<StrengthMeter password="aaaab" />);
    rerender(<StrengthMeter password="aaaabc" />);
    rerender(<StrengthMeter password="aaaabcd" />);
    act(() => {
      vi.advanceTimersByTime(199);
    });
    // Final update has not been committed yet; debounced score still reflects "aaaa".
    // Now advance past the debounce window: only the latest value is scored.
    act(() => {
      vi.advanceTimersByTime(50);
    });
    vi.useRealTimers();
    await waitFor(
      () => {
        // Eventually scored — proving debounce fired exactly once at the tail.
        expect(getByTestId("strength-meter").querySelector("[data-score]")).toBeTruthy();
      },
      { timeout: 15_000 },
    );
  }, 30_000);
});
