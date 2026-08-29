import { ApiError, getJson } from './client';
import type { EventFilters, EventsListResponse, HealthResponse, SecurityEvent } from '../types/api';

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function isFlowKey(value: unknown): boolean {
  return isObject(value)
    && typeof value.src_ip === 'string'
    && typeof value.dst_ip === 'string'
    && typeof value.protocol === 'string'
    && (typeof value.src_port === 'number' || value.src_port === null)
    && (typeof value.dst_port === 'number' || value.dst_port === null);
}

function isDetectionResult(value: unknown): boolean {
  return isObject(value)
    && typeof value.rule_id === 'string'
    && typeof value.rule_name === 'string'
    && typeof value.severity === 'string'
    && isFlowKey(value.flow_key)
    && typeof value.window_start === 'string'
    && typeof value.window_end === 'string'
    && isObject(value.evidence)
    && typeof value.explanation === 'string';
}

function isRiskScore(value: unknown): boolean {
  return isObject(value)
    && typeof value.score === 'number'
    && typeof value.level === 'string'
    && (value.flow_key === null || isFlowKey(value.flow_key))
    && (value.window_start === null || typeof value.window_start === 'string')
    && (value.window_end === null || typeof value.window_end === 'string')
    && Array.isArray(value.detections)
    && value.detections.every(isDetectionResult)
    && typeof value.explanation === 'string';
}

function isPolicyTarget(value: unknown): boolean {
  return isObject(value)
    && typeof value.ip === 'string'
    && (typeof value.port === 'number' || value.port === null)
    && typeof value.role === 'string';
}

function isResponseDecision(value: unknown): boolean {
  return isObject(value)
    && typeof value.recommended_action === 'string'
    && typeof value.allowed === 'boolean'
    && typeof value.execution_mode === 'string'
    && (value.flow_key === null || isFlowKey(value.flow_key))
    && (value.window_start === null || typeof value.window_start === 'string')
    && (value.window_end === null || typeof value.window_end === 'string')
    && typeof value.risk_score === 'number'
    && typeof value.risk_level === 'string'
    && Array.isArray(value.detection_ids)
    && value.detection_ids.every((item) => typeof item === 'string')
    && (value.target === null || isPolicyTarget(value.target))
    && typeof value.explanation === 'string';
}

function isResponseResult(value: unknown): boolean {
  return isObject(value)
    && typeof value.action === 'string'
    && typeof value.status === 'string'
    && typeof value.simulated === 'boolean'
    && (value.target === null || isPolicyTarget(value.target))
    && typeof value.message === 'string'
    && (value.error === null || typeof value.error === 'string')
    && typeof value.timestamp === 'string';
}

export function isSecurityEvent(value: unknown): value is SecurityEvent {
  return isObject(value)
    && typeof value.event_id === 'string'
    && isFlowKey(value.flow_key)
    && typeof value.window_start === 'string'
    && typeof value.window_end === 'string'
    && typeof value.recorded_at === 'string'
    && Array.isArray(value.detections)
    && value.detections.every(isDetectionResult)
    && isRiskScore(value.risk)
    && isResponseDecision(value.policy)
    && isResponseResult(value.response)
    && typeof value.lifecycle_status === 'string';
}

export function validateHealthResponse(value: unknown): HealthResponse {
  if (
    !isObject(value)
    || typeof value.status !== 'string'
    || typeof value.app_name !== 'string'
    || typeof value.app_version !== 'string'
    || typeof value.database !== 'string'
  ) {
    throw new ApiError('The API returned an invalid health record.', 'invalid_health_record');
  }

  return value as HealthResponse;
}

export function validateEventsListResponse(value: unknown): EventsListResponse {
  if (
    !isObject(value)
    || !Array.isArray(value.items)
    || !value.items.every(isSecurityEvent)
    || typeof value.count !== 'number'
    || typeof value.limit !== 'number'
  ) {
    throw new ApiError('The API returned an invalid security event record.', 'invalid_persisted_record');
  }

  return value as EventsListResponse;
}

export function validateSecurityEvent(value: unknown): SecurityEvent {
  if (!isSecurityEvent(value)) {
    throw new ApiError('The API returned an invalid security event record.', 'invalid_persisted_record');
  }

  return value;
}

export async function fetchHealth(): Promise<HealthResponse> {
  return validateHealthResponse(await getJson('/health'));
}

export async function fetchEvents(filters: EventFilters = {}): Promise<EventsListResponse> {
  const params = new URLSearchParams();
  if (filters.limit !== undefined) {
    params.set('limit', String(filters.limit));
  }
  if (filters.risk_level) {
    params.set('risk_level', filters.risk_level);
  }
  if (filters.lifecycle_status) {
    params.set('lifecycle_status', filters.lifecycle_status);
  }
  const query = params.toString();
  return validateEventsListResponse(await getJson(query ? `/events?${query}` : '/events'));
}

export async function fetchEvent(eventId: string): Promise<SecurityEvent> {
  return validateSecurityEvent(await getJson(`/events/${encodeURIComponent(eventId)}`));
}
