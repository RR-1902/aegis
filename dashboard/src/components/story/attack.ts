/**
 * The attack the story follows: the "fast_scan" scenario in app/simulation/scenarios.py with the
 * source address scripts/seed_demo_attacks.py gives it, so the engine's real output for these
 * packets is the critical event in the bundled ledger.
 */
export const ATTACK = {
  source: '203.0.113.201',
  target: '10.0.0.4',
  ports: [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200],
  spanSeconds: 0.8,
} as const;
