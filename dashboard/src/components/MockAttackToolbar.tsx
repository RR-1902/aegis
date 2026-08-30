import React, { useState } from 'react';
import type { SecurityEvent } from '../types/api';
import { soundFx } from '../utils/soundFx';

type Props = {
  onInjectEvent: (event: SecurityEvent) => void;
};

export const MockAttackToolbar: React.FC<Props> = ({ onInjectEvent }) => {
  const [lastInjected, setLastInjected] = useState<string | null>(null);

  const createMockEvent = (type: 'syn_flood' | 'port_scan' | 'icmp_storm' | 'rst_abort'): SecurityEvent => {
    const now = new Date();
    const timeIso = now.toISOString();
    const windowStart = new Date(now.getTime() - 5000).toISOString();
    const idSuffix = Math.floor(Math.random() * 90000 + 10000);

    switch (type) {
      case 'syn_flood':
        return {
          event_id: `security-event:syn-flood-${idSuffix}`,
          flow_key: {
            src_ip: `198.51.100.${Math.floor(Math.random() * 200 + 10)}`,
            dst_ip: '10.0.0.1',
            protocol: 'TCP',
            src_port: 54000 + Math.floor(Math.random() * 5000),
            dst_port: 80,
          },
          window_start: windowStart,
          window_end: timeIso,
          recorded_at: timeIso,
          detections: [
            {
              rule_id: 'syn_flood',
              rule_name: 'SYN Flood Attack (DoS Probe)',
              severity: 'high',
              flow_key: {
                src_ip: '198.51.100.44',
                dst_ip: '10.0.0.1',
                protocol: 'TCP',
                src_port: null,
                dst_port: null,
              },
              window_start: windowStart,
              window_end: timeIso,
              evidence: {
                syn_rate: (Math.random() * 100 + 120).toFixed(1),
                syn_ack_ratio: 0.995,
                total_syn_packets: 980,
              },
              explanation: 'Excessive volume of half-open TCP SYN handshakes observed without ACK responses.',
            },
          ],
          risk: {
            score: 96,
            level: 'critical',
            flow_key: null,
            window_start: null,
            window_end: null,
            detections: [],
            explanation: 'High packet velocity and 99.5% uncompleted SYN ratio triggered critical response.',
          },
          policy: {
            recommended_action: 'block_source',
            allowed: true,
            execution_mode: 'simulate',
            flow_key: null,
            window_start: null,
            window_end: null,
            risk_score: 96,
            risk_level: 'critical',
            detection_ids: ['syn_flood'],
            target: { ip: '198.51.100.44', port: null, role: 'source' },
            explanation: 'Simulated firewall action: Inject iptables DROP rule for source IP.',
          },
          response: {
            action: 'block_source',
            status: 'simulated',
            simulated: true,
            target: { ip: '198.51.100.44', port: null, role: 'source' },
            message: 'Simulated packet filter dropped ingress packets from source.',
            error: null,
            timestamp: timeIso,
          },
          lifecycle_status: 'simulated',
        };

      case 'port_scan':
        return {
          event_id: `security-event:port-scan-${idSuffix}`,
          flow_key: {
            src_ip: `203.0.113.${Math.floor(Math.random() * 200 + 10)}`,
            dst_ip: '10.0.0.2',
            protocol: 'TCP',
            src_port: 48000 + Math.floor(Math.random() * 2000),
            dst_port: null,
          },
          window_start: windowStart,
          window_end: timeIso,
          recorded_at: timeIso,
          detections: [
            {
              rule_id: 'port_scan',
              rule_name: 'Stealth SYN Port Scan (Nmap)',
              severity: 'high',
              flow_key: {
                src_ip: '203.0.113.88',
                dst_ip: '10.0.0.2',
                protocol: 'TCP',
                src_port: null,
                dst_port: null,
              },
              window_start: windowStart,
              window_end: timeIso,
              evidence: {
                unique_ports_scanned: 64,
                duration_ms: 850,
                scanned_range: '21..8080',
              },
              explanation: 'Rapid vertical port probe detected targeting system daemon listening sockets.',
            },
          ],
          risk: {
            score: 79,
            level: 'high',
            flow_key: null,
            window_start: null,
            window_end: null,
            detections: [],
            explanation: 'Reconnaissance probe detected across 64 destination ports in sub-second window.',
          },
          policy: {
            recommended_action: 'block_source',
            allowed: true,
            execution_mode: 'simulate',
            flow_key: null,
            window_start: null,
            window_end: null,
            risk_score: 79,
            risk_level: 'high',
            detection_ids: ['port_scan'],
            target: { ip: '203.0.113.88', port: null, role: 'source' },
            explanation: 'Simulated rate limiting / IP isolation applied.',
          },
          response: {
            action: 'block_source',
            status: 'simulated',
            simulated: true,
            target: { ip: '203.0.113.88', port: null, role: 'source' },
            message: 'Simulated firewall drop rule injected for reconnaissance scanner.',
            error: null,
            timestamp: timeIso,
          },
          lifecycle_status: 'simulated',
        };

      case 'icmp_storm':
        return {
          event_id: `security-event:icmp-storm-${idSuffix}`,
          flow_key: {
            src_ip: `192.0.2.${Math.floor(Math.random() * 200 + 10)}`,
            dst_ip: '10.0.0.255',
            protocol: 'ICMP',
            src_port: null,
            dst_port: null,
          },
          window_start: windowStart,
          window_end: timeIso,
          recorded_at: timeIso,
          detections: [
            {
              rule_id: 'icmp_spike',
              rule_name: 'ICMP Broadcast Flood / Smurf Vector',
              severity: 'medium',
              flow_key: {
                src_ip: '192.0.2.15',
                dst_ip: '10.0.0.255',
                protocol: 'ICMP',
                src_port: null,
                dst_port: null,
              },
              window_start: windowStart,
              window_end: timeIso,
              evidence: {
                icmp_packet_rate: 180.5,
                echo_reply_amplification: '12x',
              },
              explanation: 'Subnet broadcast ping flood detected with anomalous payload volume.',
            },
          ],
          risk: {
            score: 55,
            level: 'medium',
            flow_key: null,
            window_start: null,
            window_end: null,
            detections: [],
            explanation: 'Moderate traffic anomaly on ICMP protocol.',
          },
          policy: {
            recommended_action: 'alert_only',
            allowed: true,
            execution_mode: 'simulate',
            flow_key: null,
            window_start: null,
            window_end: null,
            risk_score: 55,
            risk_level: 'medium',
            detection_ids: ['icmp_spike'],
            target: null,
            explanation: 'Telemetry alert dispatched without packet drop.',
          },
          response: {
            action: 'alert_only',
            status: 'no_action',
            simulated: true,
            target: null,
            message: 'Alert record broadcast to security console.',
            error: null,
            timestamp: timeIso,
          },
          lifecycle_status: 'no_action',
        };

      case 'rst_abort':
        return {
          event_id: `security-event:rst-abort-${idSuffix}`,
          flow_key: {
            src_ip: `198.18.0.${Math.floor(Math.random() * 200 + 10)}`,
            dst_ip: '10.0.0.5',
            protocol: 'TCP',
            src_port: 52100,
            dst_port: 443,
          },
          window_start: windowStart,
          window_end: timeIso,
          recorded_at: timeIso,
          detections: [
            {
              rule_id: 'rst_anomaly',
              rule_name: 'Abnormal TCP RST Connection Teardown',
              severity: 'low',
              flow_key: {
                src_ip: '198.18.0.12',
                dst_ip: '10.0.0.5',
                protocol: 'TCP',
                src_port: null,
                dst_port: null,
              },
              window_start: windowStart,
              window_end: timeIso,
              evidence: {
                rst_packet_count: 38,
                rst_ratio: 0.62,
              },
              explanation: 'Unusual percentage of abruptly terminated TLS connections.',
            },
          ],
          risk: {
            score: 32,
            level: 'low',
            flow_key: null,
            window_start: null,
            window_end: null,
            detections: [],
            explanation: 'Low severity connection abort pattern.',
          },
          policy: {
            recommended_action: 'log_only',
            allowed: true,
            execution_mode: 'simulate',
            flow_key: null,
            window_start: null,
            window_end: null,
            risk_score: 32,
            risk_level: 'low',
            detection_ids: ['rst_anomaly'],
            target: null,
            explanation: 'Logged for audit record.',
          },
          response: {
            action: 'log_only',
            status: 'no_action',
            simulated: true,
            target: null,
            message: 'Audit event logged in SQLite.',
            error: null,
            timestamp: timeIso,
          },
          lifecycle_status: 'no_action',
        };
    }
  };

  const handleInject = (type: 'syn_flood' | 'port_scan' | 'icmp_storm' | 'rst_abort') => {
    soundFx.playThreatAlert();
    const event = createMockEvent(type);
    setLastInjected(`Injected [${type.toUpperCase()}] from ${event.flow_key.src_ip}`);
    onInjectEvent(event);

    setTimeout(() => {
      soundFx.playSuccessTone();
    }, 400);
  };

  return (
    <div className="swiss-box" style={{
      background: 'var(--bg-surface)',
      padding: '14px 18px',
      marginBottom: 16,
      border: '1px solid rgba(34, 197, 94, 0.3)',
      boxShadow: '0 0 15px rgba(34, 197, 94, 0.05)'
    }}>
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        flexWrap: 'wrap',
        gap: 12,
        marginBottom: 10
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <span style={{
            fontFamily: 'var(--font-pixel)',
            fontSize: 12,
            color: 'var(--terminal-green)',
            letterSpacing: '0.1em'
          }}>
            ⚡ INJECT LIVE MOCK ATTACK:
          </span>
          <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
            Simulate instant cyber attack vectors &amp; test real-time detection
          </span>
        </div>

        {lastInjected && (
          <div style={{
            fontSize: 10,
            color: 'var(--terminal-green)',
            background: 'rgba(34, 197, 94, 0.1)',
            padding: '2px 8px',
            border: '1px solid var(--terminal-green)'
          }}>
            ● {lastInjected}
          </div>
        )}
      </div>

      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <button
          type="button"
          className="btn-toggle"
          style={{
            borderColor: 'rgba(239, 68, 68, 0.4)',
            color: '#fca5a5',
            padding: '6px 12px',
            fontWeight: 700
          }}
          onClick={() => handleInject('syn_flood')}
        >
          ⚡ INJECT SYN FLOOD (CRITICAL)
        </button>

        <button
          type="button"
          className="btn-toggle"
          style={{
            borderColor: 'rgba(249, 115, 22, 0.4)',
            color: '#fdba74',
            padding: '6px 12px',
            fontWeight: 700
          }}
          onClick={() => handleInject('port_scan')}
        >
          🔍 INJECT PORT SCAN (HIGH)
        </button>

        <button
          type="button"
          className="btn-toggle"
          style={{
            borderColor: 'rgba(245, 158, 11, 0.4)',
            color: '#fde047',
            padding: '6px 12px',
            fontWeight: 700
          }}
          onClick={() => handleInject('icmp_storm')}
        >
          💥 INJECT ICMP STORM (MED)
        </button>

        <button
          type="button"
          className="btn-toggle"
          style={{
            borderColor: 'rgba(6, 182, 212, 0.4)',
            color: '#67e8f9',
            padding: '6px 12px',
            fontWeight: 700
          }}
          onClick={() => handleInject('rst_abort')}
        >
          🚨 INJECT RST ANOMALY (LOW)
        </button>
      </div>
    </div>
  );
};

export default MockAttackToolbar;
