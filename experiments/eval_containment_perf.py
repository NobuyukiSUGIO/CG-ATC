"""Containment performance evaluation (paper §V).

Measures the size of the impact set (`Impact(A_i, t)`) and the
propagation depth before and after CG-ATC's containment ladder
(§III-H) is engaged.

Workload: a star topology where one attacker `worm-0` tries to send to
`fanout` peers, then escalates risk so the scope reducer drives it to
`NETWORK_ISOLATED`.
"""

from __future__ import annotations

import json
import os
import platform
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from cgatc.containment import ImpactGraph, ScopeReducer
from cgatc.containment.impact_radius import radius_for_level
from cgatc.core.constants import TAU_4
from cgatc.core.types import AgentID
from cgatc.detection import RiskScoreUpdater, RiskWeights


def run(*, fanout: int = 50, depth: int = 3) -> dict[str, object]:
    impact = ImpactGraph()
    scope = ScopeReducer()
    risk = RiskScoreUpdater(RiskWeights())
    attacker = AgentID(b"\xaa" * 32)

    # Build a tree: attacker → fanout layer → another fanout layer …
    layers = [[attacker]]
    for d in range(depth):
        nxt: list[AgentID] = []
        for src in layers[-1]:
            for k in range(fanout):
                child = AgentID(bytes([d + 1, k % 256]) * 16)
                impact.record_send(src, child)
                nxt.append(child)
        layers.append(nxt)

    set_before = impact.impact_set(attacker, max_radius=10)
    radius_before = radius_for_level(scope.current(attacker))

    # Ramp risk well above τ_4 to trigger NETWORK_ISOLATED.  Each tick
    # decays prior risk by λ, so the asymptote of constant severity-1.0
    # is 1/(1-λ).  Use severity 3.0 to comfortably overshoot τ_4=10.
    for _ in range(40):
        risk.add_crypto(attacker, 3.0)
        r = risk.tick(attacker)
    level_after = scope.evaluate(attacker, r)
    radius_after = radius_for_level(level_after)
    set_after = impact.impact_set(attacker, max_radius=radius_after)

    return {
        "fanout": fanout,
        "depth": depth,
        "agents_reached_before": len(set_before),
        "max_radius_before": radius_before,
        "agents_reached_after_isolation": len(set_after),
        "max_radius_after": radius_after,
        "containment_level_after": level_after.name,
        "final_risk": r,
        "tau_4": TAU_4,
    }


def main() -> None:
    rows = [
        run(fanout=10, depth=3),
        run(fanout=50, depth=2),
    ]
    for r in rows:
        print(r)

    out_dir = Path(__file__).resolve().parents[1] / "results" / (
        datetime.now(timezone.utc).strftime("%Y%m%d") + "_containment_perf"
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "containment.json").write_text(json.dumps(rows, indent=2, default=str))
    (out_dir / "meta.json").write_text(json.dumps({
        "python": sys.version, "platform": platform.platform(),
        "argv": sys.argv, "cwd": os.getcwd(),
    }, indent=2))
    print(f"\nWrote results to {out_dir}")


if __name__ == "__main__":
    main()
