import { expect, test } from "vitest";

import {
  ActivityCadence,
  backoffMs,
  localCooldownMs,
  minimumIntervalMs,
} from "../../src/features/session/activity";

test("the first admissible gesture sends at once", () => {
  const cadence = new ActivityCadence();
  expect(cadence.interaction(1_000)).toBe("send");
});

test("a gesture inside the window holds, and one after it sends", () => {
  const cadence = new ActivityCadence();
  cadence.interaction(0);
  cadence.settle("accepted", 10, null);
  expect(cadence.interaction(minimumIntervalMs - 1)).toBe("hold");
  expect(cadence.interaction(minimumIntervalMs)).toBe("send");
});

test("only one request is ever in flight", () => {
  const cadence = new ActivityCadence();
  expect(cadence.interaction(0)).toBe("send");
  expect(cadence.interaction(minimumIntervalMs * 5)).toBe("hold");
  cadence.settle("accepted", minimumIntervalMs * 5, null);
  expect(cadence.dueAt(minimumIntervalMs * 6)).toBe("send");
});

/* A held gesture arms a later send; that send is still attributable to it. */
test("a deferred send exists only because a gesture armed it", () => {
  const cadence = new ActivityCadence();
  cadence.interaction(0);
  cadence.settle("accepted", 0, null);
  expect(cadence.dueAt(minimumIntervalMs * 10)).toBe("hold");
  cadence.interaction(100);
  expect(cadence.dueAt(minimumIntervalMs * 10)).toBe("send");
});

test("nothing ever becomes due without a gesture", () => {
  const cadence = new ActivityCadence();
  for (const at of [0, 1_000, minimumIntervalMs, minimumIntervalMs * 100, 10 ** 9]) {
    expect(cadence.dueAt(at), `due at ${at}`).toBe("hold");
  }
});

/* A send waits for the window and the block alike; the longer one decides. */
test("a stated limit longer than the window governs the next send", () => {
  const stated = minimumIntervalMs * 2;
  const cadence = new ActivityCadence();
  cadence.interaction(0);
  cadence.settle("limited", 0, stated);
  expect(cadence.interaction(minimumIntervalMs)).toBe("hold");
  expect(cadence.interaction(stated - 1)).toBe("hold");
  expect(cadence.interaction(stated)).toBe("send");
});

test("without a stated limit the local cooldown governs it", () => {
  expect(localCooldownMs).toBeGreaterThan(minimumIntervalMs);
  const cadence = new ActivityCadence();
  cadence.interaction(0);
  cadence.settle("limited", 0, null);
  expect(cadence.interaction(minimumIntervalMs)).toBe("hold");
  expect(cadence.interaction(localCooldownMs - 1)).toBe("hold");
  expect(cadence.interaction(localCooldownMs)).toBe("send");
});

test("a failure backs off and never retries on its own", () => {
  const cadence = new ActivityCadence();
  cadence.interaction(0);
  cadence.settle("failed", 0, null);

  const step = backoffMs[0] ?? 0;
  /* Whichever is longer, the backoff or the window, decides when a gesture may send. */
  const resume = Math.max(step, minimumIntervalMs);
  for (const at of [step, resume - 1, resume, resume * 4]) {
    expect(cadence.dueAt(at), `no self retry at ${at}ms`).toBe("hold");
  }
  expect(cadence.interaction(resume - 1)).toBe("hold");
  expect(cadence.interaction(resume)).toBe("send");
});

/* A success clears the escalation, so the next failure starts at the first step. */
test("a success resets the escalation", () => {
  const cadence = new ActivityCadence();
  expect(cadence.interaction(0)).toBe("send");
  cadence.settle("failed", 0, null);
  const first = Math.max(backoffMs[0] ?? 0, minimumIntervalMs);
  expect(cadence.interaction(first)).toBe("send");
  cadence.settle("accepted", first, null);

  const second = first + minimumIntervalMs;
  expect(cadence.interaction(second)).toBe("send");
  cadence.settle("failed", second, null);
  const again = second + Math.max(backoffMs[0] ?? 0, minimumIntervalMs);
  expect(cadence.interaction(again - 1)).toBe("hold");
  expect(cadence.interaction(again)).toBe("send");
});

/*
  Each attempt sends before it is settled, so the history is one the cadence
  could really have produced. Nothing succeeds in between, so the count escalates.
*/
test("consecutive failures escalate, then hold at the last step", () => {
  const cadence = new ActivityCadence();
  let now = 0;
  const reached: number[] = [];

  for (let attempt = 0; attempt < backoffMs.length + 1; attempt += 1) {
    expect(cadence.interaction(now), `attempt ${attempt} sends`).toBe("send");
    cadence.settle("failed", now, null);

    const expected = backoffMs[Math.min(attempt, backoffMs.length - 1)] ?? 0;
    const resume = now + Math.max(expected, minimumIntervalMs);
    expect(cadence.interaction(resume - 1), `attempt ${attempt} still blocked`).toBe("hold");
    reached.push(expected);
    now = resume;
  }
  expect(reached).toEqual([...backoffMs, backoffMs[backoffMs.length - 1]]);
});

test("a settlement without a request in flight is refused", () => {
  const cadence = new ActivityCadence();
  expect(() => cadence.settle("accepted", 0, null)).toThrow(/in flight/);
  cadence.interaction(0);
  cadence.settle("accepted", 0, null);
  expect(() => cadence.settle("accepted", 1, null)).toThrow(/in flight/);
});

test("an unauthenticated or forbidden answer disarms any pending send", () => {
  for (const outcome of ["unauthenticated", "forbidden"] as const) {
    const cadence = new ActivityCadence();
    cadence.interaction(0);
    cadence.interaction(10);
    cadence.settle(outcome, 20, null);
    expect(cadence.dueAt(minimumIntervalMs * 10), outcome).toBe("hold");
  }
});

/* The instant a waiting gesture becomes admissible, so one timer can be armed. */
test("nothing is due while nothing waits", () => {
  const cadence = new ActivityCadence();
  expect(cadence.pendingDueAt()).toBeNull();
  cadence.interaction(0);
  expect(cadence.pendingDueAt(), "in flight").toBeNull();
  cadence.settle("accepted", 0, null);
  expect(cadence.pendingDueAt(), "settled, nothing waiting").toBeNull();
});

test("a gesture during a long flight is due once that flight settles", () => {
  const cadence = new ActivityCadence();
  const flight = minimumIntervalMs * 2;
  expect(cadence.interaction(0)).toBe("send");

  /* The gesture arrives while the first request is still out. */
  expect(cadence.interaction(flight / 2)).toBe("hold");
  expect(cadence.pendingDueAt(), "nothing can be armed mid-flight").toBeNull();

  cadence.settle("accepted", flight, null);
  const due = cadence.pendingDueAt();
  expect(due).toBe(minimumIntervalMs);
  expect(cadence.dueAt(due ?? 0)).toBe("send");
  /* Exactly one send, and only because that gesture happened. */
  cadence.settle("accepted", due ?? 0, null);
  expect(cadence.pendingDueAt()).toBeNull();
});

test("a gesture during a cooldown longer than the window is due at its end", () => {
  const cadence = new ActivityCadence();
  const cooldown = minimumIntervalMs * 3;
  expect(cadence.interaction(0)).toBe("send");
  cadence.settle("limited", 0, cooldown);

  expect(cadence.interaction(minimumIntervalMs)).toBe("hold");
  expect(cadence.pendingDueAt()).toBe(cooldown);
  expect(cadence.dueAt(cooldown - 1), "not before the cooldown ends").toBe("hold");
  expect(cadence.dueAt(cooldown)).toBe("send");
});

test("a network failure drops the waiting gesture and arms nothing", () => {
  const cadence = new ActivityCadence();
  expect(cadence.interaction(0)).toBe("send");
  expect(cadence.interaction(1_000)).toBe("hold");
  cadence.settle("failed", 2_000, null);

  expect(cadence.pendingDueAt(), "no armed retry after a failure").toBeNull();
  for (const at of [minimumIntervalMs, minimumIntervalMs * 10, minimumIntervalMs * 100]) {
    expect(cadence.dueAt(at), `no spontaneous retry at ${at}`).toBe("hold");
  }
});
