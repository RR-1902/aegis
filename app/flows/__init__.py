"""Flow aggregation module for AEGIS."""

from app.flows.flow_key import FlowKeyStrategy, FlowKeyManager
from app.flows.time_window import TimeWindowManager, SlidingWindowManager
from app.flows.flow_builder import FlowBuilder, flow_builder

__all__ = [
    "FlowKeyStrategy",
    "FlowKeyManager",
    "TimeWindowManager",
    "SlidingWindowManager",
    "FlowBuilder",
    "flow_builder",
]
