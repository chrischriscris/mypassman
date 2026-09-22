// Target-identity checks for autofill — pure functions so the fail-closed
// rules are testable without the Raycast runtime. A fill may only deliver
// to an app that positively identifies itself by bundle id; anything else
// (lookup failure, missing bundle id, focus moved) aborts.

export interface TargetApp {
  name: string;
  bundleId?: string | null;
}

/** An app that positively identified itself — the only kind a fill may deliver to. */
export interface IdentifiedTarget {
  name: string;
  bundleId: string;
}

/**
 * Identify the app a fill was initiated for. Returns null when the OS
 * can't name the frontmost app or the app carries no bundle id — callers
 * must treat null as "abort before touching the secret".
 */
export function identifyTarget(app: TargetApp | null | undefined): IdentifiedTarget | null {
  if (!app?.bundleId) return null;
  return { name: app.name ?? "", bundleId: app.bundleId };
}

/**
 * Post-close re-check: delivery proceeds only when the frontmost app is
 * still the intended one. An unidentifiable app is never the intended one.
 */
export function sameTarget(
  intended: IdentifiedTarget,
  current: TargetApp | null | undefined,
): boolean {
  return identifyTarget(current)?.bundleId === intended.bundleId;
}
