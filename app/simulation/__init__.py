"""Synthetic attack simulations driven through the real AEGIS pipeline."""

from app.simulation.scenarios import SCENARIOS, Scenario, SimulationResult, is_simulated_source, run_scenario

__all__ = ["SCENARIOS", "Scenario", "SimulationResult", "is_simulated_source", "run_scenario"]
