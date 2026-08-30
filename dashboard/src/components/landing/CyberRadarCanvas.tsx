import React, { useEffect, useRef, useState } from 'react';
import { soundFx } from '../../utils/soundFx';

type Node = {
  x: number;
  y: number;
  z: number;
  label: string;
  ip: string;
  status: 'safe' | 'warning' | 'critical';
  size: number;
};

export const CyberRadarCanvas: React.FC = () => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const [activeNodesCount, setActiveNodesCount] = useState(16);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || typeof canvas.getContext !== 'function') return;
    let ctx: CanvasRenderingContext2D | null = null;
    try {
      ctx = canvas.getContext('2d');
    } catch {
      return;
    }
    if (!ctx) return;

    let animationFrameId: number;
    let angle = 0;
    let radarSweep = 0;

    // Define 3D network topology nodes
    const nodes: Node[] = [
      { x: 0, y: 0, z: 0, label: 'AEGIS_CORE', ip: '10.0.0.1', status: 'safe', size: 7 },
      { x: -90, y: -60, z: 40, label: 'GATEWAY_FW_01', ip: '192.168.1.1', status: 'safe', size: 5 },
      { x: 100, y: -80, z: -30, label: 'INGRESS_BPF_02', ip: '192.168.1.254', status: 'safe', size: 5 },
      { x: -120, y: 80, z: -50, label: 'FLOW_BUFFER_03', ip: '10.0.10.12', status: 'safe', size: 4 },
      { x: 110, y: 90, z: 60, label: 'RULE_ENGINE_04', ip: '10.0.20.4', status: 'safe', size: 5 },
      { x: -40, y: 130, z: 20, label: 'PERSIST_SQLITE', ip: '10.0.30.9', status: 'safe', size: 4 },
      { x: 60, y: -130, z: 50, label: 'REST_TELEMETRY', ip: '10.0.40.80', status: 'safe', size: 4 },
      { x: -160, y: -20, z: 10, label: 'THREAT_VECTOR_X', ip: '198.51.100.44', status: 'critical', size: 6 },
      { x: 150, y: 30, z: -40, label: 'PROBE_SCANNER_Y', ip: '203.0.113.88', status: 'warning', size: 5 },
    ];

    setActiveNodesCount(nodes.length);

    // Particle pulses
    const particles: { fromIdx: number; toIdx: number; progress: number; speed: number; color: string }[] = [
      { fromIdx: 1, toIdx: 0, progress: 0.1, speed: 0.015, color: '#22c55e' },
      { fromIdx: 2, toIdx: 0, progress: 0.4, speed: 0.02, color: '#06b6d4' },
      { fromIdx: 7, toIdx: 1, progress: 0.7, speed: 0.025, color: '#ef4444' },
      { fromIdx: 8, toIdx: 2, progress: 0.2, speed: 0.018, color: '#f59e0b' },
      { fromIdx: 0, toIdx: 4, progress: 0.6, speed: 0.022, color: '#22c55e' },
    ];

    const resize = () => {
      if (!canvas) return;
      const rect = canvas.getBoundingClientRect();
      canvas.width = rect.width * window.devicePixelRatio;
      canvas.height = rect.height * window.devicePixelRatio;
      ctx.scale(window.devicePixelRatio, window.devicePixelRatio);
    };
    resize();
    window.addEventListener('resize', resize);

    const render = () => {
      if (!canvas) return;
      const width = canvas.width / window.devicePixelRatio;
      const height = canvas.height / window.devicePixelRatio;
      const cx = width / 2;
      const cy = height / 2;

      ctx.clearRect(0, 0, width, height);

      // Background Cyber Radar Circles
      ctx.save();
      ctx.translate(cx, cy);

      // Concentric grid rings
      [40, 90, 140, 190].forEach((r, idx) => {
        ctx.beginPath();
        ctx.arc(0, 0, r, 0, Math.PI * 2);
        ctx.strokeStyle = idx === 3 ? 'rgba(34, 197, 94, 0.25)' : 'rgba(255, 255, 255, 0.05)';
        ctx.lineWidth = 1;
        ctx.setLineDash(idx % 2 === 1 ? [4, 4] : []);
        ctx.stroke();
      });
      ctx.setLineDash([]);

      // Crosshairs
      ctx.beginPath();
      ctx.moveTo(-190, 0);
      ctx.lineTo(190, 0);
      ctx.moveTo(0, -190);
      ctx.lineTo(0, 190);
      ctx.strokeStyle = 'rgba(255, 255, 255, 0.06)';
      ctx.stroke();

      // Radar Sweep Beam
      radarSweep += 0.02;
      const sweepGradient = ctx.createConicGradient(radarSweep, 0, 0);
      sweepGradient.addColorStop(0, 'rgba(34, 197, 94, 0.15)');
      sweepGradient.addColorStop(0.1, 'rgba(34, 197, 94, 0.0)');
      sweepGradient.addColorStop(1, 'rgba(34, 197, 94, 0.0)');

      ctx.fillStyle = sweepGradient;
      ctx.beginPath();
      ctx.arc(0, 0, 190, 0, Math.PI * 2);
      ctx.fill();

      // 3D Isometric Projection Matrix
      angle += 0.005;
      const cosA = Math.cos(angle);
      const sinA = Math.sin(angle);

      const projectedNodes = nodes.map((node) => {
        // Rotate around Y axis
        const rotX = node.x * cosA - node.z * sinA;
        const rotZ = node.x * sinA + node.z * cosA + 300; // perspective depth
        const rotY = node.y;

        const fov = 260 / rotZ;
        const screenX = rotX * fov;
        const screenY = rotY * fov;

        return {
          ...node,
          screenX,
          screenY,
          depth: rotZ,
          scale: fov,
        };
      });

      // Draw Connections
      ctx.strokeStyle = 'rgba(255, 255, 255, 0.08)';
      ctx.lineWidth = 1;
      for (let i = 0; i < projectedNodes.length; i++) {
        for (let j = i + 1; j < projectedNodes.length; j++) {
          const dist = Math.hypot(nodes[i].x - nodes[j].x, nodes[i].y - nodes[j].y, nodes[i].z - nodes[j].z);
          if (dist < 180 || i === 0 || j === 0) {
            ctx.beginPath();
            ctx.moveTo(projectedNodes[i].screenX, projectedNodes[i].screenY);
            ctx.lineTo(projectedNodes[j].screenX, projectedNodes[j].screenY);
            ctx.stroke();
          }
        }
      }

      // Draw Particle Packets
      particles.forEach((p) => {
        p.progress += p.speed;
        if (p.progress > 1) p.progress = 0;

        const n1 = projectedNodes[p.fromIdx];
        const n2 = projectedNodes[p.toIdx];
        if (!n1 || !n2) return;

        const px = n1.screenX + (n2.screenX - n1.screenX) * p.progress;
        const py = n1.screenY + (n2.screenY - n1.screenY) * p.progress;

        ctx.fillStyle = p.color;
        ctx.shadowColor = p.color;
        ctx.shadowBlur = 8;
        ctx.beginPath();
        ctx.arc(px, py, 3, 0, Math.PI * 2);
        ctx.fill();
        ctx.shadowBlur = 0;
      });

      // Draw Nodes
      projectedNodes.forEach((node) => {
        const color =
          node.status === 'critical'
            ? '#ef4444'
            : node.status === 'warning'
            ? '#f59e0b'
            : '#22c55e';

        // Outer glow halo
        ctx.fillStyle = color;
        ctx.shadowColor = color;
        ctx.shadowBlur = 10;
        ctx.beginPath();
        ctx.arc(node.screenX, node.screenY, node.size * node.scale * 1.2, 0, Math.PI * 2);
        ctx.fill();
        ctx.shadowBlur = 0;

        // Core white dot
        ctx.fillStyle = '#ffffff';
        ctx.beginPath();
        ctx.arc(node.screenX, node.screenY, (node.size * node.scale) / 2, 0, Math.PI * 2);
        ctx.fill();

        // Node Label
        ctx.font = '9px "Geist Mono", monospace';
        ctx.fillStyle = color;
        ctx.fillText(node.label, node.screenX + 8, node.screenY + 3);
      });

      ctx.restore();

      animationFrameId = requestAnimationFrame(render);
    };

    render();

    return () => {
      cancelAnimationFrame(animationFrameId);
      window.removeEventListener('resize', resize);
    };
  }, []);

  const handleRadarClick = () => {
    soundFx.playBeep(980, 0.08, 'sawtooth');
  };

  return (
    <div className="swiss-box" style={{ background: 'var(--bg-surface)', padding: 20, position: 'relative' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
        <div>
          <span style={{ color: 'var(--terminal-green)', fontSize: 11, letterSpacing: '0.15em', textTransform: 'uppercase' }}>
            3D SPATIAL TELEMETRY RADAR
          </span>
          <h3 style={{ fontSize: '1.2rem', color: '#ffffff', marginTop: 2 }}>ACTIVE TOPOLOGY GRID</h3>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <span className="badge badge-low">NODES: {activeNodesCount}</span>
          <span className="badge badge-critical">THREATS: 1 ISOLATED</span>
        </div>
      </div>

      <div style={{ position: 'relative', width: '100%', height: 360, background: '#000000', overflow: 'hidden' }}>
        <canvas
          ref={canvasRef}
          onClick={handleRadarClick}
          style={{ width: '100%', height: '100%', cursor: 'crosshair', display: 'block' }}
        />

        {/* Tactical HUD Overlay Metadata */}
        <div style={{
          position: 'absolute',
          bottom: 12,
          left: 12,
          fontFamily: 'var(--font-mono)',
          fontSize: 10,
          color: 'var(--text-dim)',
          background: 'rgba(0,0,0,0.7)',
          padding: '4px 8px',
          border: '1px solid var(--border-hairline)'
        }}>
          RADAR_POLAR: 360° · SWEEP: 60 RPM · RANGE: 500m
        </div>

        <div style={{
          position: 'absolute',
          top: 12,
          right: 12,
          fontFamily: 'var(--font-mono)',
          fontSize: 10,
          color: 'var(--terminal-green)',
          background: 'rgba(0,0,0,0.7)',
          padding: '4px 8px',
          border: '1px solid rgba(34,197,94,0.3)'
        }}>
          ● PACKET ROUTING ENGINE: ARMED
        </div>
      </div>
    </div>
  );
};

export default CyberRadarCanvas;
