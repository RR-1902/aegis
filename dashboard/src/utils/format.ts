export function formatDateTime(value: string | null | undefined): string {
  if (!value) {
    return '—';
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return date.toLocaleString();
}

export function formatShortId(value: string, length = 16): string {
  if (value.length <= length) {
    return value;
  }
  return `${value.slice(0, length)}…`;
}

export function formatFlowKey(flowKey: {
  src_ip: string;
  dst_ip: string;
  protocol: string;
  src_port: number | null;
  dst_port: number | null;
}): string {
  const srcPort = flowKey.src_port ?? '*';
  const dstPort = flowKey.dst_port ?? '*';
  return `${flowKey.src_ip}:${srcPort} → ${flowKey.dst_ip}:${dstPort} (${flowKey.protocol})`;
}

export function titleCase(value: string): string {
  return value
    .split('_')
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ');
}
