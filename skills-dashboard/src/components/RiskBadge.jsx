export const RISK_COLORS = {
  CRITICAL: "#c6392c",
  HIGH: "#e07b39",
  MEDIUM: "#b45309",
  LOW: "#4a9a8a",
  CLEAN: "#2f7d31",
  UNKNOWN: "#9e9e9e",
};

export const RISK_ORDER = [
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
  "CLEAN",
  "UNKNOWN",
];

export function RiskBadge({ level }) {
  const color = RISK_COLORS[level] || RISK_COLORS.UNKNOWN;
  return (
    <span
      style={{ color, borderColor: color }}
      className="inline-block px-1.5 py-0.5 text-xs font-semibold border rounded-[0.2rem] whitespace-nowrap"
    >
      {level || "UNKNOWN"}
    </span>
  );
}
