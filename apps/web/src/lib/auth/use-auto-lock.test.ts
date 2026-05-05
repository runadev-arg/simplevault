/**
 * Spec for `attachAutoLock` — the imperative core of the `useAutoLock`
 * hook. We exercise it directly (no React renderer / DOM) because the
 * web vitest config is `node` env. The hook itself is a thin
 * `useEffect(() => attachAutoLock(router), [router])` wrapper.
 *
 * Coverage:
 *   1. Idle expiry → wipe + clearToken + router.replace('/login?reason=auto_lock').
 *   2. `pointerdown` mid-window resets the timer.
 *   3. `keydown` mid-window resets the timer.
 *   4. `visibilitychange` mid-window resets the timer (treated as activity, NOT trigger).
 *   5. Cleanup detaches listeners and prevents post-unmount fires.
 *   6. `onIdle` fires at most once even if listeners are still attached.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { attachAutoLock, AUTO_LOCK_EVENTS } from "./use-auto-lock";

interface FakeDoc {
  addEventListener: ReturnType<typeof vi.fn>;
  removeEventListener: ReturnType<typeof vi.fn>;
  /** Helper for the tests — dispatch a tracked activity event. */
  dispatch: (type: string) => void;
}

function makeFakeDoc(): FakeDoc {
  const listeners = new Map<string, Set<EventListener>>();
  const add = vi.fn((type: string, fn: EventListener): void => {
    let set = listeners.get(type);
    if (!set) {
      set = new Set();
      listeners.set(type, set);
    }
    set.add(fn);
  });
  const remove = vi.fn((type: string, fn: EventListener): void => {
    listeners.get(type)?.delete(fn);
  });
  const dispatch = (type: string): void => {
    const set = listeners.get(type);
    if (!set) return;
    for (const fn of set) fn(new Event(type));
  };
  return { addEventListener: add, removeEventListener: remove, dispatch };
}

const IDLE_MS = 900_000;

let router: { replace: ReturnType<typeof vi.fn> };
let onWipe: ReturnType<typeof vi.fn>;
let onClearToken: ReturnType<typeof vi.fn>;
let doc: FakeDoc;

beforeEach(() => {
  vi.useFakeTimers();
  router = { replace: vi.fn() };
  onWipe = vi.fn();
  onClearToken = vi.fn();
  doc = makeFakeDoc();
});

afterEach(() => {
  vi.useRealTimers();
});

describe("attachAutoLock", () => {
  it("attaches the three tracked activity listeners", () => {
    const cleanup = attachAutoLock(router, { idleMs: IDLE_MS, doc, onWipe, onClearToken });
    const types = doc.addEventListener.mock.calls.map((c) => c[0] as string);
    expect(types).toEqual(["pointerdown", "keydown", "visibilitychange"]);
    expect(types).toEqual([...AUTO_LOCK_EVENTS]);
    cleanup();
  });

  it("fires idle handler exactly at IDLE_MS — wipe + clearToken + router.replace", () => {
    const cleanup = attachAutoLock(router, { idleMs: IDLE_MS, doc, onWipe, onClearToken });

    // Just before the deadline → no fire.
    vi.advanceTimersByTime(IDLE_MS - 1);
    expect(onWipe).not.toHaveBeenCalled();
    expect(onClearToken).not.toHaveBeenCalled();
    expect(router.replace).not.toHaveBeenCalled();

    // Cross the deadline.
    vi.advanceTimersByTime(2);
    expect(onWipe).toHaveBeenCalledTimes(1);
    expect(onClearToken).toHaveBeenCalledTimes(1);
    expect(router.replace).toHaveBeenCalledTimes(1);
    expect(router.replace).toHaveBeenCalledWith("/login?reason=auto_lock");

    cleanup();
  });

  it("pointerdown mid-window resets the timer", () => {
    const cleanup = attachAutoLock(router, { idleMs: IDLE_MS, doc, onWipe, onClearToken });

    vi.advanceTimersByTime(IDLE_MS / 2);
    doc.dispatch("pointerdown");

    // Original deadline would have fired; reset means it must not.
    vi.advanceTimersByTime(IDLE_MS - 1);
    expect(onWipe).not.toHaveBeenCalled();

    // Cross the new deadline.
    vi.advanceTimersByTime(2);
    expect(onWipe).toHaveBeenCalledTimes(1);
    expect(router.replace).toHaveBeenCalledWith("/login?reason=auto_lock");

    cleanup();
  });

  it("keydown mid-window resets the timer", () => {
    const cleanup = attachAutoLock(router, { idleMs: IDLE_MS, doc, onWipe, onClearToken });

    vi.advanceTimersByTime(IDLE_MS - 100);
    doc.dispatch("keydown");

    vi.advanceTimersByTime(IDLE_MS - 1);
    expect(onWipe).not.toHaveBeenCalled();

    vi.advanceTimersByTime(2);
    expect(onWipe).toHaveBeenCalledTimes(1);

    cleanup();
  });

  it("visibilitychange resets the timer (activity, NOT trigger)", () => {
    const cleanup = attachAutoLock(router, { idleMs: IDLE_MS, doc, onWipe, onClearToken });

    vi.advanceTimersByTime(IDLE_MS - 100);
    doc.dispatch("visibilitychange");

    // Critical: did NOT fire as a trigger.
    expect(onWipe).not.toHaveBeenCalled();
    expect(router.replace).not.toHaveBeenCalled();

    // Timer was reset.
    vi.advanceTimersByTime(IDLE_MS - 1);
    expect(onWipe).not.toHaveBeenCalled();
    vi.advanceTimersByTime(2);
    expect(onWipe).toHaveBeenCalledTimes(1);

    cleanup();
  });

  it("cleanup detaches listeners + prevents post-unmount fires", () => {
    const cleanup = attachAutoLock(router, { idleMs: IDLE_MS, doc, onWipe, onClearToken });

    cleanup();

    // All listeners removed.
    expect(doc.removeEventListener).toHaveBeenCalledTimes(AUTO_LOCK_EVENTS.length);

    vi.advanceTimersByTime(IDLE_MS * 2);
    expect(onWipe).not.toHaveBeenCalled();
    expect(onClearToken).not.toHaveBeenCalled();
    expect(router.replace).not.toHaveBeenCalled();
  });

  it("idle handler fires at most once", () => {
    const cleanup = attachAutoLock(router, { idleMs: IDLE_MS, doc, onWipe, onClearToken });

    vi.advanceTimersByTime(IDLE_MS + 1);
    expect(onWipe).toHaveBeenCalledTimes(1);

    // Even if more time passes / activity arrives, no second fire.
    doc.dispatch("pointerdown");
    vi.advanceTimersByTime(IDLE_MS * 2);
    expect(onWipe).toHaveBeenCalledTimes(1);
    expect(onClearToken).toHaveBeenCalledTimes(1);
    expect(router.replace).toHaveBeenCalledTimes(1);

    cleanup();
  });
});
