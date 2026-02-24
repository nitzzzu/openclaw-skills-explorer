import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";
import { MetricCard } from "../components/MetricCard";
import { SectionTitle } from "../components/SectionTitle";

const CAT_COLORS = [
  "#d2836e",
  "#4a9a8a",
  "#4a5568",
  "#d4a843",
  "#7b68ee",
  "#5f9ea0",
  "#cd853f",
  "#6b8e23",
  "#bc8f8f",
  "#8fbc8f",
];

function fmt(n) {
  return Number(n).toLocaleString();
}

export function OverviewSection({ data }) {
  const { stats, monthly, categories } = data;

  const totalActive = fmt(Number(stats.total_active));
  const totalDeleted = fmt(Number(stats.total_deleted));
  const totalCats = fmt(Number(stats.total_categories));
  const active = Number(stats.total_active);
  const scanned = Number(stats.total_scanned);
  const scannedPct =
    active > 0 ? ((scanned / active) * 100).toFixed(1) + "%" : "0%";
  const highRisk = fmt(Number(stats.high_risk));

  const topCat = categories[0];
  const top3Cats = categories
    .slice(0, 3)
    .map((c) => c.name)
    .join(", ");

  return (
    <div className="space-y-8">
      {/* KPI Strip */}
      <div>
        <SectionTitle sub="Snapshot of the OpenClaw agentic skills registry">
          Catalog Overview
        </SectionTitle>
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-2">
          <MetricCard
            label="Active Skills"
            value={totalActive}
            sub="in HEAD commit"
          />
          <MetricCard
            label="Deleted"
            value={totalDeleted}
            sub="removed from repo"
          />
          <MetricCard
            label="Categories"
            value={totalCats}
            sub="skill domains"
          />
          <MetricCard
            label="Scanned"
            value={scannedPct}
            sub={`${fmt(stats.total_scanned)} skills`}
          />
          <MetricCard
            label="High / Critical"
            value={highRisk}
            sub="security issues found"
            accent={Number(stats.high_risk) > 0 ? "negative" : "positive"}
          />
        </div>
      </div>

      {/* Growth */}
      <div>
        <SectionTitle sub="Skills added to the registry per day">
          Growth Timeline
        </SectionTitle>
        <ResponsiveContainer width="100%" height={200}>
          <AreaChart
            data={monthly}
            margin={{ top: 4, right: 16, bottom: 0, left: 0 }}
          >
            <defs>
              <linearGradient id="growGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#d2836e" stopOpacity={0.4} />
                <stop offset="95%" stopColor="#d2836e" stopOpacity={0.05} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#e4e0d6" />
            <XAxis
              dataKey="month"
              tick={{ fontSize: 10, fontFamily: "IBM Plex Mono" }}
              tickFormatter={(v) => (v ? v.slice(5) : "")}
              interval="preserveStartEnd"
            />
            <YAxis
              tick={{ fontSize: 11, fontFamily: "IBM Plex Mono" }}
              width={50}
            />
            <Tooltip
              contentStyle={{
                background: "#fbf7eb",
                borderColor: "#393939",
                fontFamily: "IBM Plex Mono",
                fontSize: 12,
              }}
              formatter={(v, n, p) => [
                v.toLocaleString(),
                `Skills added on ${p.payload.month}`,
              ]}
            />
            <Area
              type="monotone"
              dataKey="added"
              stroke="#d2836e"
              strokeWidth={2}
              fill="url(#growGrad)"
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      {/* Category Distribution */}
      <div>
        <SectionTitle sub="Top 20 skill categories by count">
          Category Distribution
        </SectionTitle>
        <ResponsiveContainer width="100%" height={360}>
          <BarChart
            data={categories}
            layout="vertical"
            margin={{ top: 4, right: 60, bottom: 4, left: 140 }}
          >
            <CartesianGrid
              strokeDasharray="3 3"
              stroke="#e4e0d6"
              horizontal={false}
            />
            <XAxis
              type="number"
              tick={{ fontSize: 11, fontFamily: "IBM Plex Mono" }}
            />
            <YAxis
              type="category"
              dataKey="name"
              tick={{ fontSize: 11, fontFamily: "IBM Plex Mono" }}
              width={138}
            />
            <Tooltip
              contentStyle={{
                background: "#fbf7eb",
                borderColor: "#393939",
                fontFamily: "IBM Plex Mono",
                fontSize: 12,
              }}
              formatter={(v) => [v.toLocaleString(), "Skills"]}
            />
            <Bar dataKey="cnt" radius={[0, 2, 2, 0]}>
              {categories.map((_, i) => (
                <Cell key={i} fill={CAT_COLORS[i % CAT_COLORS.length]} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>

      {/* Insight Cards */}
      <div>
        <SectionTitle sub="Key signals from the catalog">Insights</SectionTitle>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="border border-dashed border-[#2f7d31] p-4">
            <div className="text-[11px] uppercase tracking-wide text-[#2f7d31] mb-2 font-semibold">
              What looks healthy
            </div>
            <ul className="space-y-1.5 text-[12px] text-[#474747]">
              <li>
                → <strong>{totalActive}</strong> active skills cataloged across{" "}
                <strong>{totalCats}</strong> domains
              </li>
              <li>
                → Largest category: <strong>{topCat?.name}</strong> (
                {fmt(topCat?.cnt)} skills)
              </li>
              <li>
                → Only {scannedPct} scanned yet — security posture still
                discoverable
              </li>
              <li>→ Top 3 domains: {top3Cats}</li>
            </ul>
          </div>
          <div className="border border-dashed border-[#c6392c] p-4">
            <div className="text-[11px] uppercase tracking-wide text-[#c6392c] mb-2 font-semibold">
              Needs attention
            </div>
            <ul className="space-y-1.5 text-[12px] text-[#474747]">
              <li>
                → <strong>{highRisk}</strong> skills flagged HIGH or CRITICAL
                risk
              </li>
              <li>
                → Most skills (<strong>{fmt(active - scanned)}</strong>) are
                UNKNOWN — scanning is essential
              </li>
              <li>
                → Low scan coverage ({scannedPct}) — blind spots remain in the
                catalog
              </li>
              <li>
                → Run{" "}
                <code className="bg-[#eee9d7] px-1">
                  skills_catalog.py --full-rescan
                </code>{" "}
                to scan all skills
              </li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
}
