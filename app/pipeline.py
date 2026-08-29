"""End-to-end runtime orchestration for AEGIS."""

from __future__ import annotations

from dataclasses import dataclass, field
import logging
from typing import List, Optional

from app.capture.packet_capture import PacketCapture
from app.config.settings import settings
from app.detection.engine import DetectionEngine
from app.flows.flow_builder import FlowBuilder
from app.models.flow import FeatureObservation
from app.models.security_event import SecurityEvent
from app.policy.engine import PolicyEngine
from app.response.engine import ResponseEngine
from app.scoring.risk_scorer import RiskScorer
from app.storage.security_event_store import SQLiteSecurityEventStore, SecurityEventStore

logger = logging.getLogger(__name__)


@dataclass
class PipelineStatistics:
    """Minimal runtime counters for AEGISPipeline."""

    observations_received: int = 0
    observations_without_detections: int = 0
    detections_produced: int = 0
    events_persisted: int = 0
    detection_failures: int = 0
    scoring_failures: int = 0
    policy_failures: int = 0
    response_failures: int = 0
    event_construction_failures: int = 0
    persistence_failures: int = 0


@dataclass
class AEGISPipeline:
    """Thin application service that wires the current AEGIS runtime stages."""

    packet_capture: Optional[PacketCapture] = None
    flow_builder: Optional[FlowBuilder] = None
    detection_engine: Optional[DetectionEngine] = None
    risk_scorer: Optional[RiskScorer] = None
    policy_engine: Optional[PolicyEngine] = None
    response_engine: Optional[ResponseEngine] = None
    event_store: Optional[SecurityEventStore] = None
    flow_key_strategy: str = "five_tuple"
    use_sliding_windows: bool = False
    _running: bool = field(default=False, init=False)
    _accept_observations: bool = field(default=False, init=False)
    stats: PipelineStatistics = field(default_factory=PipelineStatistics, init=False)

    def __post_init__(self) -> None:
        if self.packet_capture is None:
            self.packet_capture = PacketCapture(
                interface=settings.capture_interface,
                capture_filter=settings.capture_filter,
            )
        if self.flow_builder is None:
            self.flow_builder = FlowBuilder(
                flow_key_strategy=self.flow_key_strategy,
                window_seconds=settings.flow_window_seconds,
                flow_timeout_seconds=settings.flow_timeout_seconds,
                use_sliding_windows=self.use_sliding_windows,
            )
        if self.detection_engine is None:
            self.detection_engine = DetectionEngine()
        if self.risk_scorer is None:
            self.risk_scorer = RiskScorer()
        if self.policy_engine is None:
            self.policy_engine = PolicyEngine(safe_mode=settings.safe_mode)
        if self.response_engine is None:
            self.response_engine = ResponseEngine(safe_mode=settings.safe_mode)
        if self.event_store is None:
            self.event_store = SQLiteSecurityEventStore(settings.database_url)

    @property
    def is_running(self) -> bool:
        return self._running

    def start(self) -> bool:
        if self._running:
            logger.warning("AEGISPipeline already running")
            return False

        self._wire_callbacks()
        started = self.packet_capture.start()
        if not started:
            logger.error("Failed to start packet capture for AEGISPipeline")
            return False

        self._accept_observations = True
        self._running = True
        logger.info("AEGISPipeline started")
        return True

    def stop(self) -> None:
        if not self._running:
            return

        logger.info("Stopping AEGISPipeline")
        self._accept_observations = False
        self.packet_capture.stop()
        self._running = False
        logger.info("AEGISPipeline stopped")

    def _wire_callbacks(self) -> None:
        self.packet_capture.packet_callback = self.flow_builder.add_packet
        self.flow_builder.set_feature_observation_callback(self._handle_feature_observation)

    def _handle_feature_observation(self, observation: FeatureObservation) -> None:
        if not self._accept_observations:
            logger.debug(
                "Ignoring finalized observation after pipeline stop: %s [%s, %s)",
                observation.flow_key,
                observation.window_start.isoformat(),
                observation.window_end.isoformat(),
            )
            return

        self.stats.observations_received += 1
        logger.info(
            "Finalized observation received for %s [%s, %s)",
            observation.flow_key,
            observation.window_start.isoformat(),
            observation.window_end.isoformat(),
        )

        detections = self._run_detection(observation)
        if detections is None:
            return
        if not detections:
            self.stats.observations_without_detections += 1
            logger.debug(
                "No detections for observation %s [%s, %s)",
                observation.flow_key,
                observation.window_start.isoformat(),
                observation.window_end.isoformat(),
            )
            return

        risk = self._run_scoring(observation, detections)
        if risk is None:
            return

        decision = self._run_policy(observation, risk)
        if decision is None:
            return

        response = self._run_response(observation, decision)
        if response is None:
            return

        event = self._build_security_event(observation, detections, risk, decision, response)
        if event is None:
            return

        self._persist_security_event(event)

    def _run_detection(self, observation: FeatureObservation):
        try:
            detections = self.detection_engine.evaluate(observation)
            self.stats.detections_produced += len(detections)
            logger.info(
                "Detection produced %d result(s) for %s [%s, %s)",
                len(detections),
                observation.flow_key,
                observation.window_start.isoformat(),
                observation.window_end.isoformat(),
            )
            return detections
        except Exception as exc:
            self.stats.detection_failures += 1
            logger.error(
                "Detection failed for observation %s [%s, %s): %s",
                observation.flow_key,
                observation.window_start.isoformat(),
                observation.window_end.isoformat(),
                exc,
            )
            return None

    def _run_scoring(self, observation: FeatureObservation, detections):
        try:
            risk = self.risk_scorer.score(detections)
            logger.info(
                "Risk score %d (%s) for %s [%s, %s)",
                risk.score,
                risk.level.name,
                observation.flow_key,
                observation.window_start.isoformat(),
                observation.window_end.isoformat(),
            )
            return risk
        except Exception as exc:
            self.stats.scoring_failures += 1
            logger.error(
                "Scoring failed for observation %s [%s, %s): %s",
                observation.flow_key,
                observation.window_start.isoformat(),
                observation.window_end.isoformat(),
                exc,
            )
            return None

    def _run_policy(self, observation: FeatureObservation, risk):
        try:
            decision = self.policy_engine.decide(risk)
            logger.info(
                "Policy recommended %s with execution mode %s for %s [%s, %s)",
                decision.recommended_action.name,
                decision.execution_mode.name,
                observation.flow_key,
                observation.window_start.isoformat(),
                observation.window_end.isoformat(),
            )
            return decision
        except Exception as exc:
            self.stats.policy_failures += 1
            logger.error(
                "Policy failed for observation %s [%s, %s): %s",
                observation.flow_key,
                observation.window_start.isoformat(),
                observation.window_end.isoformat(),
                exc,
            )
            return None

    def _run_response(self, observation: FeatureObservation, decision):
        try:
            response = self.response_engine.handle(decision)
            logger.info(
                "Response returned %s for %s [%s, %s)",
                response.status.name,
                observation.flow_key,
                observation.window_start.isoformat(),
                observation.window_end.isoformat(),
            )
            return response
        except Exception as exc:
            self.stats.response_failures += 1
            logger.error(
                "Response handling failed for observation %s [%s, %s): %s",
                observation.flow_key,
                observation.window_start.isoformat(),
                observation.window_end.isoformat(),
                exc,
            )
            return None

    def _build_security_event(self, observation, detections, risk, decision, response):
        try:
            return SecurityEvent.create(
                flow_key=observation.flow_key,
                window_start=observation.window_start,
                window_end=observation.window_end,
                detections=detections,
                risk=risk,
                policy=decision,
                response=response,
            )
        except Exception as exc:
            self.stats.event_construction_failures += 1
            logger.error(
                "SecurityEvent construction failed for observation %s [%s, %s): %s",
                observation.flow_key,
                observation.window_start.isoformat(),
                observation.window_end.isoformat(),
                exc,
            )
            return None

    def _persist_security_event(self, event: SecurityEvent) -> None:
        try:
            self.event_store.save(event)
            self.stats.events_persisted += 1
            logger.info("Persisted security event %s", event.event_id)
        except Exception as exc:
            self.stats.persistence_failures += 1
            logger.error("Failed to persist security event %s: %s", event.event_id, exc)

    def process_parsed_packet(self, packet) -> None:
        """Test/helper entrypoint for feeding one ParsedPacket into the runtime."""
        self.flow_builder.add_packet(packet)

    def get_statistics(self) -> dict:
        return {
            "is_running": self._running,
            "accept_observations": self._accept_observations,
            "pipeline": self.stats.__dict__.copy(),
            "capture": self.packet_capture.get_statistics() if hasattr(self.packet_capture, "get_statistics") else {},
            "flows": self.flow_builder.get_statistics() if hasattr(self.flow_builder, "get_statistics") else {},
        }
