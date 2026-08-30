import React, { useState } from 'react';
import { soundFx } from '../../utils/soundFx';

type ByteField = {
  id: string;
  name: string;
  layer: 'L2' | 'L3' | 'L4' | 'Payload';
  hexRange: string;
  bytes: string[];
  decodedValue: string;
  rfcRef: string;
  explanation: string;
};

const DISSECTOR_FIELDS: ByteField[] = [
  {
    id: 'ip_ver_ihl',
    name: 'IP Version & Header Length (IHL)',
    layer: 'L3',
    hexRange: 'Byte 00',
    bytes: ['45'],
    decodedValue: 'IPv4 (Version 4) · Header Length: 20 bytes (5 × 32-bit words)',
    rfcRef: 'RFC 791 (IPv4 Protocol Specification)',
    explanation: 'The high nibble (4) declares the IPv4 protocol. The low nibble (5) indicates a 20-byte standard header without variable IP options.',
  },
  {
    id: 'ip_len',
    name: 'IPv4 Total Length',
    layer: 'L3',
    hexRange: 'Bytes 02–03',
    bytes: ['00', '3C'],
    decodedValue: '60 Bytes (Header 20B + TCP Header 40B)',
    rfcRef: 'RFC 791 §3.1',
    explanation: 'Total datagram length in octets including both IP header and the encapsulated transport layer segment.',
  },
  {
    id: 'ip_ttl',
    name: 'Time to Live (TTL)',
    layer: 'L3',
    hexRange: 'Byte 08',
    bytes: ['40'],
    decodedValue: '64 Hops (Standard Linux Kernel Default)',
    rfcRef: 'RFC 791 / RFC 1700',
    explanation: 'Decremented by each intermediate router. Prevents packets from circulating indefinitely in network routing loops.',
  },
  {
    id: 'ip_proto',
    name: 'Encapsulated Protocol Number',
    layer: 'L3',
    hexRange: 'Byte 09',
    bytes: ['06'],
    decodedValue: '0x06 (IPPROTO_TCP)',
    rfcRef: 'IANA Assigned Internet Protocol Numbers',
    explanation: 'Directs the AEGIS protocol parser to route the encapsulated payload directly into the TCP state machine handler.',
  },
  {
    id: 'ip_src',
    name: 'Source IPv4 Address',
    layer: 'L3',
    hexRange: 'Bytes 12–15',
    bytes: ['C0', 'A8', '01', '69'],
    decodedValue: '192.168.1.105',
    rfcRef: 'RFC 1918 (Private Address Allocation)',
    explanation: 'Originating endpoint IPv4 address. Used by the AEGIS flow engine as the primary source key in 5-tuple canonical hashing.',
  },
  {
    id: 'ip_dst',
    name: 'Destination IPv4 Address',
    layer: 'L3',
    hexRange: 'Bytes 16–19',
    bytes: ['0A', '00', '00', '02'],
    decodedValue: '10.0.0.2',
    rfcRef: 'RFC 1918',
    explanation: 'Target system address monitored by the AEGIS intrusion grid sensor.',
  },
  {
    id: 'tcp_ports',
    name: 'TCP Source & Destination Ports',
    layer: 'L4',
    hexRange: 'Bytes 20–23',
    bytes: ['C0', '00', '00', '50'],
    decodedValue: 'Src Port: 49152 (Ephemeral) ➔ Dst Port: 80 (HTTP / WWW)',
    rfcRef: 'RFC 793 (Transmission Control Protocol)',
    explanation: 'Port 80 indicates an incoming HTTP connection attempt initiated from high ephemeral port 49152.',
  },
  {
    id: 'tcp_flags',
    name: 'TCP Control Bits / Flags',
    layer: 'L4',
    hexRange: 'Bytes 33',
    bytes: ['02'],
    decodedValue: '0x02 [SYN = 1, ACK = 0, RST = 0, FIN = 0]',
    rfcRef: 'RFC 793 / RFC 3168 (ECN)',
    explanation: 'SYN handshake initiation. In a high volume scenario, an abnormal ratio of SYN without subsequent ACK triggers the AEGIS SYN Flood rule.',
  },
  {
    id: 'tcp_window',
    name: 'TCP Window Size',
    layer: 'L4',
    hexRange: 'Bytes 34–35',
    bytes: ['72', '10'],
    decodedValue: '29,200 Bytes',
    rfcRef: 'RFC 793 §3.1',
    explanation: 'Number of data octets beginning with the one indicated in the acknowledgment field which the sender of this segment is willing to accept.',
  },
];

export const PacketDissectorSection: React.FC = () => {
  const [activeField, setActiveField] = useState<ByteField>(DISSECTOR_FIELDS[7]); // default to TCP flags

  const handleSelectField = (field: ByteField) => {
    soundFx.playKeyClick();
    setActiveField(field);
  };

  return (
    <section className="section-wrapper" id="dissector-section">
      <div className="section-header">
        <span className="section-index">03 // PROTOCOL DISSECTION</span>
        <h2 className="section-heading">RAW HEX &amp; BITFIELD INSPECTOR</h2>
        <p className="section-subtext">
          Interactive byte-level packet dissection. Click any protocol segment to inspect binary header offsets, RFC validation, and rule correlation.
        </p>
      </div>

      <div className="swiss-box" style={{ padding: 24, background: 'var(--bg-surface)' }}>
        {/* Hex Matrix View */}
        <div style={{ marginBottom: 24 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8, fontSize: 11 }}>
            <span style={{ color: 'var(--text-dim)', textTransform: 'uppercase' }}>RAW CAPTURED ETHERNET FRAME (HEX DUMP)</span>
            <span style={{ color: 'var(--terminal-green)', fontSize: 10 }}>● 60 OCTETS CAPTURED</span>
          </div>

          <div style={{
            background: 'var(--bg-void)',
            padding: 16,
            border: '1px solid var(--border-hairline)',
            overflowX: 'auto',
            fontFamily: 'var(--font-mono)',
            fontSize: 12,
            lineHeight: 2,
          }}>
            <div style={{ color: 'var(--text-dim)', fontSize: 10, borderBottom: '1px solid var(--border-hairline)', paddingBottom: 4, marginBottom: 8 }}>
              OFFSET&nbsp;&nbsp;00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F&nbsp;&nbsp;ASCII
            </div>

            {/* Row 0x0000 */}
            <div>
              <span style={{ color: 'var(--text-dim)' }}>0x0000:&nbsp;&nbsp;</span>
              {DISSECTOR_FIELDS[0].bytes.map((b, i) => (
                <span
                  key={i}
                  className={`hex-byte ip-header ${activeField.id === 'ip_ver_ihl' ? 'highlighted' : ''}`}
                  onClick={() => handleSelectField(DISSECTOR_FIELDS[0])}
                >
                  {b}
                </span>
              ))}
              <span className="hex-byte" style={{ color: 'var(--text-dim)' }}>00</span>
              {DISSECTOR_FIELDS[1].bytes.map((b, i) => (
                <span
                  key={i}
                  className={`hex-byte ip-header ${activeField.id === 'ip_len' ? 'highlighted' : ''}`}
                  onClick={() => handleSelectField(DISSECTOR_FIELDS[1])}
                >
                  {b}
                </span>
              ))}
              <span className="hex-byte" style={{ color: 'var(--text-dim)' }}>1C 46 40 00</span>
              {DISSECTOR_FIELDS[2].bytes.map((b, i) => (
                <span
                  key={i}
                  className={`hex-byte ip-header ${activeField.id === 'ip_ttl' ? 'highlighted' : ''}`}
                  onClick={() => handleSelectField(DISSECTOR_FIELDS[2])}
                >
                  {b}
                </span>
              ))}
              {DISSECTOR_FIELDS[3].bytes.map((b, i) => (
                <span
                  key={i}
                  className={`hex-byte ip-header ${activeField.id === 'ip_proto' ? 'highlighted' : ''}`}
                  onClick={() => handleSelectField(DISSECTOR_FIELDS[3])}
                >
                  {b}
                </span>
              ))}
              <span className="hex-byte" style={{ color: 'var(--text-dim)' }}>B1 E6</span>
              {DISSECTOR_FIELDS[4].bytes.map((b, i) => (
                <span
                  key={i}
                  className={`hex-byte ip-header ${activeField.id === 'ip_src' ? 'highlighted' : ''}`}
                  onClick={() => handleSelectField(DISSECTOR_FIELDS[4])}
                >
                  {b}
                </span>
              ))}
            </div>

            {/* Row 0x0010 */}
            <div>
              <span style={{ color: 'var(--text-dim)' }}>0x0010:&nbsp;&nbsp;</span>
              {DISSECTOR_FIELDS[5].bytes.map((b, i) => (
                <span
                  key={i}
                  className={`hex-byte ip-header ${activeField.id === 'ip_dst' ? 'highlighted' : ''}`}
                  onClick={() => handleSelectField(DISSECTOR_FIELDS[5])}
                >
                  {b}
                </span>
              ))}
              {DISSECTOR_FIELDS[6].bytes.map((b, i) => (
                <span
                  key={i}
                  className={`hex-byte tcp-header ${activeField.id === 'tcp_ports' ? 'highlighted' : ''}`}
                  onClick={() => handleSelectField(DISSECTOR_FIELDS[6])}
                >
                  {b}
                </span>
              ))}
              <span className="hex-byte" style={{ color: 'var(--text-dim)' }}>00 00 00 00 00 00 00 00 A0</span>
              {DISSECTOR_FIELDS[7].bytes.map((b, i) => (
                <span
                  key={i}
                  className={`hex-byte flags ${activeField.id === 'tcp_flags' ? 'highlighted' : ''}`}
                  onClick={() => handleSelectField(DISSECTOR_FIELDS[7])}
                >
                  {b}
                </span>
              ))}
              {DISSECTOR_FIELDS[8].bytes.map((b, i) => (
                <span
                  key={i}
                  className={`hex-byte tcp-header ${activeField.id === 'tcp_window' ? 'highlighted' : ''}`}
                  onClick={() => handleSelectField(DISSECTOR_FIELDS[8])}
                >
                  {b}
                </span>
              ))}
            </div>
          </div>
        </div>

        {/* Oscilloscope Waveform & Live Bitfield Analyzer Card */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'minmax(0, 1fr) minmax(0, 1fr)',
          gap: 20,
          marginBottom: 20
        }}>
          {/* Left: Oscilloscope Stream Visualizer */}
          <div className="swiss-box" style={{ background: '#000000', padding: 12, border: '1px solid var(--border-hairline)' }}>
            <div style={{ position: 'relative', overflow: 'hidden', height: 180, background: '#000000' }}>
              <img
                src="/assets/aegis_packet_matrix.jpg"
                alt="AEGIS Packet Stream Signal Oscilloscope"
                style={{
                  width: '100%',
                  height: '100%',
                  objectFit: 'cover',
                  filter: 'contrast(1.1) brightness(1.05)'
                }}
              />
              <div style={{
                position: 'absolute',
                top: 6,
                right: 6,
                background: 'rgba(0,0,0,0.8)',
                padding: '2px 6px',
                fontFamily: 'var(--font-mono)',
                fontSize: 9,
                color: 'var(--terminal-green)',
                border: '1px solid rgba(34,197,94,0.3)'
              }}>
                OSCILLOSCOPE: 874.3K PKTS/S
              </div>
            </div>
          </div>

          {/* Right: Selected Field Breakdown Drawer */}
          <div style={{
            background: 'var(--bg-void)',
            border: '1px solid var(--terminal-green)',
            padding: 16,
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'space-between'
          }}>
            <div>
              <div style={{ color: 'var(--terminal-green)', fontSize: 10, textTransform: 'uppercase', marginBottom: 4 }}>
                BITFIELD OFFSET: {activeField.hexRange} [{activeField.layer}]
              </div>
              <h3 style={{ fontSize: '1.15rem', color: '#ffffff', marginBottom: 6 }}>{activeField.name}</h3>
              <p style={{ color: 'var(--text-muted)', fontSize: 11, lineHeight: 1.5, marginBottom: 8 }}>
                {activeField.explanation}
              </p>
              <div style={{ fontSize: 10, color: 'var(--terminal-cyan)' }}>
                STANDARDS: {activeField.rfcRef}
              </div>
            </div>

            <div style={{
              background: '#070a0e',
              border: '1px solid var(--border-hairline)',
              padding: 10,
              marginTop: 10
            }}>
              <div style={{ fontSize: 9, color: 'var(--text-dim)', textTransform: 'uppercase' }}>
                DECODED PAYLOAD VALUE
              </div>
              <div style={{ color: '#ffffff', fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 700, marginTop: 2 }}>
                {activeField.decodedValue}
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};

export default PacketDissectorSection;
