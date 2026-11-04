"""Where is the event log incomplete?

Rules that conclude from the *absence* of an event (no review, no matching gateway record)
must not trust that absence across a log gap, and count-based rules should account for
events they never saw. This uses the monotonic `sequence` numbers to locate gaps.
"""
from __future__ import annotations

from bisect import bisect_left, bisect_right
from datetime import timedelta

from app.schemas import NormalizedEvent
from app.timeutil import parse_iso


class LogCoverage:
    def __init__(self, events: list[NormalizedEvent]):
        ordered = sorted((e for e in events if e.sequence > 0), key=lambda e: e.sequence)
        self.seqs = [e.sequence for e in ordered]
        self.times = [parse_iso(e.timestamp) for e in ordered]
        self.known = len(self.seqs) >= 2

    @property
    def ratio(self) -> float:
        """Share of expected events actually present (1.0 when sequences are absent or complete)."""
        if not self.known:
            return 1.0
        span = self.seqs[-1] - self.seqs[0] + 1
        return len(self.seqs) / span if span else 1.0

    def missing_between(self, a: NormalizedEvent, b: NormalizedEvent) -> int:
        """Events missing strictly between two logged events (by sequence)."""
        if not self.known or a.sequence <= 0 or b.sequence <= 0:
            return 0
        lo, hi = sorted((a.sequence, b.sequence))
        present = bisect_left(self.seqs, hi) - bisect_right(self.seqs, lo)
        return max(0, hi - lo - 1 - present)

    def missing_around(self, event: NormalizedEvent, seconds: float) -> int:
        """Events missing in the time window event ± seconds, bracketed by the nearest logged neighbours."""
        if not self.known:
            return 0
        t, window = parse_iso(event.timestamp), timedelta(seconds=seconds)
        lo_i = max(0, bisect_left(self.times, t - window) - 1)
        hi_i = min(len(self.seqs) - 1, bisect_right(self.times, t + window))
        if hi_i <= lo_i:
            return 0
        return max(0, (self.seqs[hi_i] - self.seqs[lo_i] + 1) - (hi_i - lo_i + 1))

    def local_ratio(self, a: NormalizedEvent, b: NormalizedEvent) -> float:
        """Coverage between two logged events. Loss is often bursty, so this beats the run-wide average."""
        if not self.known or a.sequence <= 0 or b.sequence <= 0:
            return 1.0
        lo, hi = sorted((a.sequence, b.sequence))
        present = bisect_right(self.seqs, hi) - bisect_left(self.seqs, lo)
        return present / (hi - lo + 1)

    def estimate(self, observed: int, min_ratio: float = 0.6, span: tuple[NormalizedEvent, NormalizedEvent] | None = None) -> float:
        """Estimated true count of something seen `observed` times, if coverage is good enough to extrapolate.

        With `span`, coverage is measured locally between those two events. Losses before the first or after the last
        seen occurrence can't be bracketed and are not extrapolated.
        """
        r = self.local_ratio(*span) if span else self.ratio
        return observed / r if r >= min_ratio else float(observed)
