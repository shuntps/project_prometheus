/*
  The cadence of the activity signal, with no DOM and no timer of its own. The
  caller feeds it real gestures and the current instant; it only ever answers.
*/
export const minimumIntervalMs = 30_000;
export const localCooldownMs = 60_000;
export const backoffMs = [5_000, 15_000, 60_000] as const;

export type ActivityDecision = "send" | "hold";

export type ActivityOutcome = "accepted" | "unauthenticated" | "forbidden" | "limited" | "failed";

/*
  Leading edge: the first admissible gesture sends at once. A gesture during the
  window or during a flight arms one later send, still attributable to it.
*/
export class ActivityCadence {
  private lastSentAt: number | null = null;
  private inFlight = false;
  private blockedUntil = 0;
  private failures = 0;
  private pendingSince: number | null = null;

  /* Called for a gesture already checked as visible, focused and admissible. */
  interaction(now: number): ActivityDecision {
    if (this.admissible(now)) {
      this.begin(now);
      return "send";
    }
    this.pendingSince = now;
    return "hold";
  }

  /* Nothing here fires on its own: a due send exists only if a gesture armed it. */
  dueAt(now: number): ActivityDecision {
    if (this.pendingSince === null || !this.admissible(now)) {
      return "hold";
    }
    this.begin(now);
    return "send";
  }

  /*
    The instant a gesture already received becomes admissible, so the caller can
    arm one timer for exactly it. Null while nothing waits or a request is out.
  */
  pendingDueAt(): number | null {
    if (this.pendingSince === null || this.inFlight) {
      return null;
    }
    const afterWindow = this.lastSentAt === null ? 0 : this.lastSentAt + minimumIntervalMs;
    return Math.max(this.blockedUntil, afterWindow);
  }

  settle(outcome: ActivityOutcome, now: number, retryAfterMs: number | null): void {
    if (!this.inFlight) {
      throw new Error("activity settled without a request in flight");
    }
    this.inFlight = false;
    switch (outcome) {
      case "accepted":
        this.failures = 0;
        return;
      case "limited":
        this.failures = 0;
        this.blockedUntil = now + (retryAfterMs ?? localCooldownMs);
        return;
      case "failed": {
        const step = backoffMs[Math.min(this.failures, backoffMs.length - 1)] ?? localCooldownMs;
        this.failures += 1;
        this.blockedUntil = now + step;
        /* A backoff is not a retry: only a later gesture may send again. */
        this.pendingSince = null;
        return;
      }
      default:
        this.pendingSince = null;
    }
  }

  private admissible(now: number): boolean {
    if (this.inFlight || now < this.blockedUntil) {
      return false;
    }
    return this.lastSentAt === null || now - this.lastSentAt >= minimumIntervalMs;
  }

  private begin(now: number): void {
    this.lastSentAt = now;
    this.inFlight = true;
    this.pendingSince = null;
  }
}
