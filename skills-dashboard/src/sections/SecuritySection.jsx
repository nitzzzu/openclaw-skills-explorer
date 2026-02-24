import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";
import { SectionTitle } from "../components/SectionTitle";
import { RiskBadge, RISK_COLORS } from "../components/RiskBadge";

const SEV_COLORS = {
  CRITICAL: "#c6392c",
  HIGH: "#e07b39",
  MEDIUM: "#b45309",
  LOW: "#4a9a8a",
  INFO: "#9e9e9e",
};

function fmt(n) {
  return Number(n).toLocaleString();
}

const RULE_LABELS = {
  PI: "Prompt Injection",
  CRED: "Credentials Leak",
  EXFIL: "Data Exfiltration",
  EXEC: "Code Execution",
  SC: "Supply Chain",
};

export function SecuritySection({ data }) {
  const { riskLevels, riskiest, findingsBySev, findingsByRule } = data;

  const totalFindings = findingsBySev.reduce((a, r) => a + r.cnt, 0);
  const criticalFindings =
    findingsBySev.find((r) => r.name === "CRITICAL")?.cnt || 0;
  const highFindings = findingsBySev.find((r) => r.name === "HIGH")?.cnt || 0;

  // expand risk levels for pie
  const pieData = riskLevels.map((r) => ({
    name: r.level,
    value: r.cnt,
    color: RISK_COLORS[r.level] || "#9e9e9e",
  }));

  // Rule category labels
  const enrichedRules = findingsByRule.map((r) => ({
    ...r,
    label: RULE_LABELS[r.name] || r.name,
  }));

  return (
    <div className="space-y-8">
      <div>
        <SectionTitle
          sub={`${fmt(totalFindings)} total findings across ${data.riskiest.length} scanned skills`}
        >
          Security Overview
        </SectionTitle>

        {/* Totals strip */}
        <div className="flex flex-wrap gap-4 mb-6">
          {[
            {
              label: "Total Findings",
              value: fmt(totalFindings),
              color: "#141414",
            },
            {
              label: "Critical",
              value: fmt(criticalFindings),
              color: "#c6392c",
            },
            { label: "High", value: fmt(highFindings), color: "#e07b39" },
          ].map(({ label, value, color }) => (
            <div
              key={label}
              className="border border-dashed border-[#393939] px-4 py-2"
            >
              <div className="text-[10px] text-[#6b6b6b] uppercase">
                {label}
              </div>
              <div className="text-xl font-bold" style={{ color }}>
                {value}
              </div>
            </div>
          ))}
        </div>

        {/* Risk distribution + findings severity side by side */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <div className="text-[11px] uppercase text-[#6b6b6b] mb-2 tracking-wide">
              Risk level distribution
            </div>
            <ResponsiveContainer width="100%" height={240}>
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={55}
                  outerRadius={90}
                  dataKey="value"
                  nameKey="name"
                  label={({ name, percent }) =>
                    percent > 0.01
                      ? `${name} ${(percent * 100).toFixed(0)}%`
                      : ""
                  }
                  labelLine={false}
                >
                  {pieData.map((entry, i) => (
                    <Cell key={i} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    background: "#fbf7eb",
                    borderColor: "#393939",
                    fontFamily: "IBM Plex Mono",
                    fontSize: 12,
                  }}
                  formatter={(v) => [v.toLocaleString(), "Skills"]}
                />
              </PieChart>
            </ResponsiveContainer>
            {/* legend */}
            <div className="flex flex-wrap gap-2 mt-1">
              {pieData.map((d) => (
                <div
                  key={d.name}
                  className="flex items-center gap-1 text-[11px]"
                >
                  <div
                    className="w-2.5 h-2.5 rounded-sm"
                    style={{ background: d.color }}
                  />
                  <span>{d.name}</span>
                  <span className="text-[#9e9e9e]">({fmt(d.value)})</span>
                </div>
              ))}
            </div>
          </div>

          <div>
            <div className="text-[11px] uppercase text-[#6b6b6b] mb-2 tracking-wide">
              Findings by severity
            </div>
            <ResponsiveContainer width="100%" height={200}>
              <BarChart
                data={findingsBySev}
                margin={{ top: 4, right: 16, bottom: 4, left: 0 }}
              >
                <CartesianGrid
                  strokeDasharray="3 3"
                  stroke="#e4e0d6"
                  vertical={false}
                />
                <XAxis
                  dataKey="name"
                  tick={{ fontSize: 11, fontFamily: "IBM Plex Mono" }}
                />
                <YAxis
                  tick={{ fontSize: 11, fontFamily: "IBM Plex Mono" }}
                  width={45}
                />
                <Tooltip
                  contentStyle={{
                    background: "#fbf7eb",
                    borderColor: "#393939",
                    fontFamily: "IBM Plex Mono",
                    fontSize: 12,
                  }}
                  formatter={(v) => [v.toLocaleString(), "Findings"]}
                />
                <Bar dataKey="cnt" radius={[2, 2, 0, 0]}>
                  {findingsBySev.map((entry, i) => (
                    <Cell key={i} fill={SEV_COLORS[entry.name] || "#9e9e9e"} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>

            {/* findings by rule type */}
            <div className="text-[11px] uppercase text-[#6b6b6b] mt-4 mb-2 tracking-wide">
              Findings by rule type
            </div>
            <div className="space-y-1.5">
              {enrichedRules.map((r) => (
                <div key={r.name} className="flex items-center gap-2">
                  <div className="text-[11px] w-32 text-[#474747] truncate">
                    {r.label}
                  </div>
                  <div className="flex-1 bg-[#e4e0d6] rounded-sm overflow-hidden h-3">
                    <div
                      className="h-full bg-[#d2836e]"
                      style={{ width: `${(r.cnt / totalFindings) * 100}%` }}
                    />
                  </div>
                  <div className="text-[11px] w-8 text-right text-[#6b6b6b]">
                    {r.cnt}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Riskiest Skills Table */}
      <div>
        <SectionTitle sub="Skills with confirmed security findings, sorted by risk and count">
          Riskiest Skills
        </SectionTitle>
        <div className="overflow-x-auto">
          <table className="w-full text-[11px] border-collapse">
            <thead>
              <tr className="border-b border-dashed border-[#393939]">
                <th className="text-left py-1.5 pr-4 text-[#6b6b6b] font-semibold uppercase tracking-wide w-1/3">
                  Skill
                </th>
                <th className="text-left py-1.5 pr-4 text-[#6b6b6b] font-semibold uppercase tracking-wide">
                  Author
                </th>
                <th className="text-left py-1.5 pr-4 text-[#6b6b6b] font-semibold uppercase tracking-wide">
                  Category
                </th>
                <th className="text-left py-1.5 pr-4 text-[#6b6b6b] font-semibold uppercase tracking-wide">
                  Risk
                </th>
                <th className="text-right py-1.5 text-[#6b6b6b] font-semibold uppercase tracking-wide">
                  Findings
                </th>
              </tr>
            </thead>
            <tbody>
              {riskiest.map((row, i) => (
                <tr
                  key={row.skill_path}
                  className={`border-b border-[#e4e0d6] hover:bg-[#f4f0e4] transition-colors ${i % 2 === 0 ? "" : "bg-[#f9f5ee]"}`}
                >
                  <td className="py-1.5 pr-4 font-mono text-[#3b6fd4] truncate max-w-[220px]">
                    {row.skill_path}
                  </td>
                  <td className="py-1.5 pr-4 text-[#474747]">
                    {row.skill_author}
                  </td>
                  <td className="py-1.5 pr-4 text-[#6b6b6b] truncate max-w-[120px]">
                    {row.category}
                  </td>
                  <td className="py-1.5 pr-4">
                    <RiskBadge level={row.level} />
                  </td>
                  <td
                    className="py-1.5 text-right font-semibold tabular-nums"
                    style={{
                      color:
                        row.level === "CRITICAL"
                          ? "#c6392c"
                          : row.level === "HIGH"
                            ? "#e07b39"
                            : "#b45309",
                    }}
                  >
                    {fmt(row.findings)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
