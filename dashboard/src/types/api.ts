export type HealthResponse = {
  status: string;
  app_name: string;
  app_version: string;
  database: string;
};

export type FlowKey = {
  src_ip: string;
  dst_ip: string;
  protocol: string;
  src_port: number | null;
  dst_port: number | null;
};

export type DetectionResult = {
  rule_id: string;
  rule_name: string;
  severity: string;
  flow_key: FlowKey;
  window_start: string;
  window_end: string;
  evidence: Record<string, unknown>;
  explanation: string;
};

export type RiskScore = {
  score: number;
  level: string;
  flow_key: FlowKey | null;
  window_start: string | null;
  window_end: string | null;
  detections: DetectionResult[];
  explanation: string;
};

export type PolicyTarget = {
  ip: string;
  port: number | null;
  role: string;
};

export type ResponseDecision = {
  recommended_action: string;
  allowed: boolean;
  execution_mode: string;
  flow_key: FlowKey | null;
  window_start: string | null;
  window_end: string | null;
  risk_score: number;
  risk_level: string;
  detection_ids: string[];
  target: PolicyTarget | null;
  explanation: string;
};

export type ResponseResult = {
  action: string;
  status: string;
  simulated: boolean;
  target: PolicyTarget | null;
  message: string;
  error: string | null;
  timestamp: string;
};

export type SecurityEvent = {
  event_id: string;
  flow_key: FlowKey;
  window_start: string;
  window_end: string;
  recorded_at: string;
  detections: DetectionResult[];
  risk: RiskScore;
  policy: ResponseDecision;
  response: ResponseResult;
  lifecycle_status: string;
};

export type EventsListResponse = {
  items: SecurityEvent[];
  count: number;
  limit: number;
};

export type EventFilters = {
  risk_level?: 'low' | 'medium' | 'high' | 'critical';
  lifecycle_status?: 'no_action' | 'simulated' | 'rejected';
  limit?: number;
};
