"""Seed aegis.db with demo security events produced by the real AEGIS engine.

Runs every scenario in app/simulation/scenarios.py: synthetic packets built in memory and fed
through the same flow builder, rules, scorer, policy engine, response engine and event store as
the live runtime. Nothing is sent on the network and no event is written by hand, so every
stored score, decision and response is one the engine produced.

Run from the repository root:
    python -m scripts.seed_demo_attacks
    python -m scripts.seed_demo_attacks --database sqlite:///aegis.db
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone

from app.simulation.scenarios import SCENARIOS, run_scenario
from app.storage.security_event_store import SQLiteSecurityEventStore


SPACING = timedelta(minutes=7)

# Fixed sources keep the bundled demo stable; the story on the website follows the fast scan.
SOURCES = {
    "syn_flood": "198.51.100.44",
    "port_scan": "203.0.113.88",
    "fast_scan": "203.0.113.201",
    "slow_scan": "192.0.2.15",
    "benign": "192.0.2.20",
}


def main() -> None:
    arguments = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    arguments.add_argument("--database", default="sqlite:///aegis.db", help="SQLite URL to write to")
    options = arguments.parse_args()

    store = SQLiteSecurityEventStore(options.database)
    now = datetime.now(timezone.utc)
    stored = []
    for index, scenario_id in enumerate(SCENARIOS):
        moment = now - SPACING * (len(SCENARIOS) - index)
        result = run_scenario(scenario_id, store, now=moment, source_ip=SOURCES.get(scenario_id))
        stored.extend(result.events)
        print(f"{result.scenario.name:<20} {result.packet_count:>3} packets from {result.source_ip:<15} -> {len(result.events)} event(s)")

    print(f"\nStored {len(stored)} security event(s) in {options.database}")
    for event in stored:
        rules = " + ".join(f"{d.rule_name} ({d.severity.value})" for d in event.detections)
        print(
            f"  {event.risk.score:>3} {event.risk.level.value:<8} {rules:<40} "
            f"{event.policy.recommended_action.value} -> {event.response.status.value}"
        )


if __name__ == "__main__":
    main()
