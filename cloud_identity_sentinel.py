#!/usr/bin/env python3
"""
Cloud Identity Sentinel — Agentic AI Starter Project
=====================================================
A self-contained simulation of an AI Agent that detects "Impossible Travel"
security threats by mimicking the Observation → Thought → Action reasoning
loop used by large-language-model-based agents.

Author : Starter-Project Template
License: MIT
"""

import json
import math
from datetime import datetime

# ─────────────────────────────────────────────────────────────────────────────
# 1. SIMULATED LOG DATA (the "environment" the agent observes)
# ─────────────────────────────────────────────────────────────────────────────

SAMPLE_LOGS = [
    {
        "event_id": "EVT-1001",
        "timestamp": "2026-02-12T08:00:00Z",
        "user": "jdoe@acme.com",
        "action": "LOGIN_SUCCESS",
        "source_ip": "203.120.12.45",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    },
    {
        "event_id": "EVT-1002",
        "timestamp": "2026-02-12T08:05:00Z",
        "user": "jdoe@acme.com",
        "action": "LOGIN_SUCCESS",
        "source_ip": "51.15.42.78",
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    },
    {
        "event_id": "EVT-1003",
        "timestamp": "2026-02-12T09:30:00Z",
        "user": "asmith@acme.com",
        "action": "LOGIN_SUCCESS",
        "source_ip": "172.58.90.12",
        "user_agent": "Mozilla/5.0 (X11; Linux x86_64)",
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# 2. TOOLS — the "Hands" of the Agent
#    These are callable functions the agent's reasoning loop can invoke,
#    just like an LLM that has been given tool-use / function-calling access.
# ─────────────────────────────────────────────────────────────────────────────

# Mock IP → geolocation database
_IP_GEO_DB = {
    "203.120.12.45": {"city": "Singapore", "country": "Singapore", "lat": 1.3521, "lon": 103.8198},
    "51.15.42.78":   {"city": "London",    "country": "United Kingdom", "lat": 51.5074, "lon": -0.1278},
    "172.58.90.12":  {"city": "New York",  "country": "United States",  "lat": 40.7128, "lon": -74.0060},
}

# Maximum speed a human can realistically travel (commercial jet ≈ 900 km/h).
# Anything above this between two logins is flagged as impossible travel.
MAX_TRAVEL_SPEED_KMH = 900


def get_ip_location(ip: str) -> dict:
    """TOOL: Look up the geographic location of an IP address.

    In production this would call a real GeoIP API (e.g. MaxMind, ip-api).
    Here we return data from our mock database.
    """
    location = _IP_GEO_DB.get(ip)
    if location is None:
        return {"error": f"No geolocation data found for IP {ip}"}
    return location


def calculate_distance_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """TOOL: Calculate the great-circle distance between two points using the
    Haversine formula.  Returns distance in kilometres."""
    R = 6371  # Earth radius in km
    d_lat = math.radians(lat2 - lat1)
    d_lon = math.radians(lon2 - lon1)
    a = (
        math.sin(d_lat / 2) ** 2
        + math.cos(math.radians(lat1))
        * math.cos(math.radians(lat2))
        * math.sin(d_lon / 2) ** 2
    )
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def calculate_required_speed_kmh(distance_km: float, time_delta_hours: float) -> float:
    """TOOL: Determine how fast someone would need to travel to cover
    *distance_km* in *time_delta_hours*."""
    if time_delta_hours <= 0:
        return float("inf")
    return distance_km / time_delta_hours


# ─────────────────────────────────────────────────────────────────────────────
# 3. TOOL REGISTRY — the agent's "toolbox" it can look up at runtime
# ─────────────────────────────────────────────────────────────────────────────

TOOL_REGISTRY = {
    "get_ip_location": {
        "function": get_ip_location,
        "description": "Returns city, country, lat, lon for a given IP address.",
    },
    "calculate_distance_km": {
        "function": calculate_distance_km,
        "description": "Calculates great-circle distance (km) between two lat/lon pairs.",
    },
    "calculate_required_speed_kmh": {
        "function": calculate_required_speed_kmh,
        "description": "Calculates required travel speed given distance and time.",
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# 4. THE AGENT — the "Brain" (simulated LLM reasoning loop)
# ─────────────────────────────────────────────────────────────────────────────

class AgentAction:
    """Represents a single action the agent decides to take."""

    def __init__(self, tool_name: str, tool_args: dict, thought: str):
        self.tool_name = tool_name
        self.tool_args = tool_args
        self.thought = thought


class CloudIdentitySentinel:
    """An agentic security analyst that processes authentication logs and
    detects impossible-travel anomalies using a Reasoning Loop:

        OBSERVE  →  THINK  →  ACT  →  DECIDE  (repeat)

    Each step is printed so you can follow the agent's chain-of-thought.
    """

    def __init__(self, tool_registry: dict):
        self.tools = tool_registry
        self.memory: list[dict] = []  # scratchpad the agent writes to
        self.alerts: list[dict] = []  # final security alerts

    # ── helper: pretty-print agent thoughts ──────────────────────────────
    @staticmethod
    def _log(phase: str, message: str) -> None:
        icons = {
            "OBSERVE": "🔍",
            "THINK": "🧠",
            "ACT": "🛠️",
            "RESULT": "📦",
            "DECIDE": "⚖️",
            "ALERT": "🚨",
        }
        icon = icons.get(phase, "  ")
        print(f"  {icon}  [{phase}]  {message}")

    # ── core: execute a tool by name ─────────────────────────────────────
    def _execute_tool(self, action: AgentAction) -> dict:
        """Look up a tool in the registry and execute it."""
        entry = self.tools.get(action.tool_name)
        if entry is None:
            return {"error": f"Unknown tool: {action.tool_name}"}
        return entry["function"](**action.tool_args)

    # ── core: the planning / reasoning loop ──────────────────────────────
    def _plan_actions_for_log(self, log_entry: dict) -> list[AgentAction]:
        """Simulate the LLM's planning step.

        A real LLM would look at the log entry, consult its system prompt,
        and emit a structured list of tool calls.  Here we replicate that
        logic with deterministic rules that mirror what the LLM would do.
        """
        actions: list[AgentAction] = []
        ip = log_entry.get("source_ip")
        if ip:
            actions.append(
                AgentAction(
                    tool_name="get_ip_location",
                    tool_args={"ip": ip},
                    thought=f"I see an IP address ({ip}) in this log entry. "
                            f"I should call get_ip_location to find out where "
                            f"this login originated.",
                )
            )
        return actions

    def _plan_comparison(self, prev: dict, curr: dict) -> list[AgentAction]:
        """Plan the distance + speed check between two enriched log entries."""
        actions: list[AgentAction] = []

        prev_loc = prev.get("location", {})
        curr_loc = curr.get("location", {})
        if "lat" in prev_loc and "lat" in curr_loc:
            actions.append(
                AgentAction(
                    tool_name="calculate_distance_km",
                    tool_args={
                        "lat1": prev_loc["lat"],
                        "lon1": prev_loc["lon"],
                        "lat2": curr_loc["lat"],
                        "lon2": curr_loc["lon"],
                    },
                    thought=f"Now I need to calculate the distance between "
                            f"{prev_loc['city']} and {curr_loc['city']} to see "
                            f"if the travel is physically possible.",
                )
            )
        return actions

    # ── the main agentic loop ────────────────────────────────────────────
    def analyze(self, logs: list[dict]) -> list[dict]:
        """Run the full Observe → Think → Act → Decide loop over a list of
        authentication log entries.

        Returns a list of security alerts (may be empty if nothing is wrong).
        """
        print("=" * 72)
        print("  CLOUD IDENTITY SENTINEL — Agentic Impossible-Travel Detector")
        print("=" * 72)

        # Group logs by user
        user_events: dict[str, list[dict]] = {}
        for entry in logs:
            user_events.setdefault(entry["user"], []).append(entry)

        for user, events in user_events.items():
            # Sort events chronologically
            events.sort(key=lambda e: e["timestamp"])

            print(f"\n{'─' * 72}")
            print(f"  Analyzing user: {user}  ({len(events)} event(s))")
            print(f"{'─' * 72}")

            enriched_events: list[dict] = []

            for event in events:
                # ── OBSERVE ──────────────────────────────────────────────
                self._log("OBSERVE", f"Reading log entry {event['event_id']}: "
                          f"{event['action']} from {event['source_ip']} "
                          f"at {event['timestamp']}")

                # ── THINK → plan which tools to call ─────────────────────
                planned = self._plan_actions_for_log(event)
                enriched = {**event, "location": {}}

                for action in planned:
                    # ── THINK (show reasoning) ───────────────────────────
                    self._log("THINK", action.thought)

                    # ── ACT (execute tool) ───────────────────────────────
                    self._log("ACT", f"Calling tool: {action.tool_name}"
                              f"({json.dumps(action.tool_args)})")
                    result = self._execute_tool(action)
                    self._log("RESULT", f"{action.tool_name} returned: "
                              f"{json.dumps(result)}")

                    if "error" not in result:
                        enriched["location"] = result

                enriched_events.append(enriched)

                # ── DECIDE: compare with previous event ──────────────────
                if len(enriched_events) >= 2:
                    prev = enriched_events[-2]
                    curr = enriched_events[-1]

                    self._log("THINK", f"User {user} has multiple logins. "
                              f"I should check if travel between "
                              f"{prev['location'].get('city', '?')} and "
                              f"{curr['location'].get('city', '?')} is "
                              f"physically possible in the elapsed time.")

                    # Plan and execute distance calculation
                    comparison_actions = self._plan_comparison(prev, curr)
                    distance_km = 0.0

                    for action in comparison_actions:
                        self._log("THINK", action.thought)
                        self._log("ACT", f"Calling tool: {action.tool_name}"
                                  f"({json.dumps(action.tool_args)})")
                        result = self._execute_tool(action)
                        distance_km = result if isinstance(result, float) else 0.0
                        self._log("RESULT", f"Distance = {distance_km:,.1f} km")

                    # Calculate time difference
                    fmt = "%Y-%m-%dT%H:%M:%SZ"
                    t1 = datetime.strptime(prev["timestamp"], fmt)
                    t2 = datetime.strptime(curr["timestamp"], fmt)
                    hours = (t2 - t1).total_seconds() / 3600

                    # Plan and execute speed calculation
                    speed_action = AgentAction(
                        tool_name="calculate_required_speed_kmh",
                        tool_args={"distance_km": distance_km,
                                   "time_delta_hours": hours},
                        thought=f"The logins are {hours * 60:.0f} minutes apart "
                                f"over {distance_km:,.1f} km. Let me calculate "
                                f"the required travel speed.",
                    )
                    self._log("THINK", speed_action.thought)
                    self._log("ACT", f"Calling tool: {speed_action.tool_name}"
                              f"({json.dumps(speed_action.tool_args)})")
                    speed = self._execute_tool(speed_action)
                    self._log("RESULT", f"Required speed = {speed:,.1f} km/h")

                    # ── DECIDE ───────────────────────────────────────────
                    if speed > MAX_TRAVEL_SPEED_KMH:
                        severity = "CRITICAL"
                        verdict = (
                            f"IMPOSSIBLE TRAVEL detected! {user} would need "
                            f"to travel at {speed:,.1f} km/h to get from "
                            f"{prev['location'].get('city', '?')} to "
                            f"{curr['location'].get('city', '?')} in "
                            f"{hours * 60:.0f} minutes. This exceeds the "
                            f"maximum realistic speed of {MAX_TRAVEL_SPEED_KMH} km/h."
                        )
                        alert = {
                            "severity": severity,
                            "user": user,
                            "from_location": prev["location"].get("city", "?"),
                            "to_location": curr["location"].get("city", "?"),
                            "distance_km": round(distance_km, 1),
                            "time_minutes": round(hours * 60, 1),
                            "required_speed_kmh": round(speed, 1),
                            "event_ids": [prev["event_id"], curr["event_id"]],
                            "verdict": verdict,
                        }
                        self.alerts.append(alert)
                        self._log("DECIDE", f"Severity → {severity}")
                        self._log("ALERT", verdict)
                    else:
                        self._log("DECIDE", "Travel speed is within normal "
                                  "limits. No alert generated.")

        # ── Summary ──────────────────────────────────────────────────────
        print(f"\n{'=' * 72}")
        print(f"  ANALYSIS COMPLETE — {len(self.alerts)} alert(s) generated")
        print(f"{'=' * 72}")
        for i, alert in enumerate(self.alerts, 1):
            print(f"\n  Alert #{i}")
            print(f"    Severity : {alert['severity']}")
            print(f"    User     : {alert['user']}")
            print(f"    From     : {alert['from_location']}")
            print(f"    To       : {alert['to_location']}")
            print(f"    Distance : {alert['distance_km']:,} km")
            print(f"    Time gap : {alert['time_minutes']} min")
            print(f"    Speed req: {alert['required_speed_kmh']:,} km/h")
            print(f"    Events   : {', '.join(alert['event_ids'])}")
            print(f"    Verdict  : {alert['verdict']}")

        return self.alerts


# ─────────────────────────────────────────────────────────────────────────────
# 5. ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    sentinel = CloudIdentitySentinel(tool_registry=TOOL_REGISTRY)
    alerts = sentinel.analyze(SAMPLE_LOGS)

    # Exit with non-zero status if critical alerts were raised
    if any(a["severity"] == "CRITICAL" for a in alerts):
        raise SystemExit(1)
