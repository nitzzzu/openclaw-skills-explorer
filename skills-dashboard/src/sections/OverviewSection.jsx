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
import { useWindowWidth } from "../hooks/useWindowWidth";

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

function fmtSize(bytes) {
  const b = Number(bytes);
  if (!b) return "0 B";
  if (b < 1024) return `${b} B`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
  if (b < 1024 * 1024 * 1024) return `${(b / (1024 * 1024)).toFixed(1)} MB`;
  return `${(b / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

const RISK_COLORS = {
  CRITICAL: "#c6392c",
  HIGH: "#d2836e",
  MEDIUM: "#d4a843",
  CLEAN: "#4a9a8a",
  UNKNOWN: "#9e9e9e",
};

const THREAT_COLORS = ["#7b68ee", "#d2836e", "#c6392c", "#d4a843", "#4a9a8a"];

export function OverviewSection({ data }) {
  const windowWidth = useWindowWidth();
  const isMobile = windowWidth < 640;

  const {
    stats,
    monthly,
    categories,
    riskLevels,
    findingsByRule,
    browseSkills,
  } = data;

  const totalActive = fmt(Number(stats.total_active));
  const totalDeleted = fmt(Number(stats.total_deleted));
  const totalCats = fmt(Number(stats.total_categories));
  const active = Number(stats.total_active);
  const scanned = Number(stats.total_scanned);
  const scannedPct =
    active > 0 ? ((scanned / active) * 100).toFixed(1) + "%" : "0%";
  const highRisk = fmt(Number(stats.high_risk));

  // Corpus stats
  const totalSizeBytes = Number(stats.total_size_bytes ?? 0);
  const totalFiles = Number(stats.total_files ?? 0);
  const totalScripts = Number(stats.total_scripts ?? 0);
  const totalMds = Number(stats.total_mds ?? 0);
  const avgSizeBytes = Number(stats.avg_size_bytes ?? 0);
  const skillsWithScripts = Number(stats.skills_with_scripts ?? 0);
  const scriptPct =
    active > 0 ? ((skillsWithScripts / active) * 100).toFixed(1) + "%" : "0%";
  const avgFilesPerSkill = active > 0 ? (totalFiles / active).toFixed(1) : "0";

  const topCat = categories[0];
  const top3Cats = categories
    .slice(0, 3)
    .map((c) => c.name)
    .join(", ");

  // Metadata quality
  const noVersionCount = Number(stats.no_version_count ?? 0);
  const noDescCount = Number(stats.no_desc_count ?? 0);
  const zeroSizeCount = Number(stats.zero_size_count ?? 0);
  const noVersionPct =
    active > 0 ? ((noVersionCount / active) * 100).toFixed(0) + "%" : "0%";
  const noDescPct =
    active > 0 ? ((noDescCount / active) * 100).toFixed(0) + "%" : "0%";
  const peakDay = monthly.length
    ? monthly.reduce((a, b) => (a.added > b.added ? a : b))
    : null;

  // Category risk ratios (computed from browseSkills)
  const catRiskMap = browseSkills.reduce((acc, s) => {
    const cat = s.category || "Other";
    if (!acc[cat]) acc[cat] = { name: cat, total: 0, risky: 0 };
    acc[cat].total++;
    if (["CRITICAL", "HIGH"].includes(s.level)) acc[cat].risky++;
    return acc;
  }, {});
  const catRisk = Object.values(catRiskMap)
    .filter((c) => c.total >= 30)
    .map((c) => ({ ...c, risky_pct: Math.round((c.risky * 100) / c.total) }))
    .sort((a, b) => b.total - a.total)
    .slice(0, 12);

  // Risk level display order
  const riskOrder = ["CRITICAL", "HIGH", "MEDIUM", "CLEAN", "UNKNOWN"];
  const riskSorted = [...(riskLevels || [])].sort(
    (a, b) => riskOrder.indexOf(a.level) - riskOrder.indexOf(b.level),
  );
  const totalRiskScanned = riskSorted.reduce((s, r) => s + r.cnt, 0);

  // Top threat categories (friendly labels)
  const threatLabels = {
    supply_chain: "Supply Chain",
    data_exfiltration: "Data Exfiltration",
    credential_exposure: "Credential Theft",
    malicious_execution: "Malicious Execution",
    prompt_injection: "Prompt Injection",
  };
  const findingsCats = (findingsByRule || []).map((r) => ({
    name: threatLabels[r.name] || r.name,
    cnt: r.cnt,
  }));

  return (
    <div className="space-y-8">
      {/* KPI Strip */}
      <div>
        <SectionTitle sub="Snapshot of the ClawEye agentic skills registry">
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

      {/* Corpus KPI strip */}
      <div>
        <SectionTitle sub="Aggregate size and content breakdown across all active skills">
          Corpus Stats
        </SectionTitle>
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-2">
          <MetricCard
            label="Total Size"
            value={fmtSize(totalSizeBytes)}
            sub="all skill folders combined"
          />
          <MetricCard
            label="Avg Size / Skill"
            value={fmtSize(avgSizeBytes)}
            sub="mean folder size"
          />
          <MetricCard
            label="Total Files"
            value={fmt(totalFiles)}
            sub={`~${avgFilesPerSkill} files/skill`}
          />
          <MetricCard
            label="Scripts (sh/py)"
            value={fmt(totalScripts)}
            sub={`${scriptPct} of skills have scripts`}
          />
          <MetricCard
            label="Markdown Docs"
            value={fmt(totalMds)}
            sub="total .md files"
          />
          <MetricCard
            label="Skills w/ Scripts"
            value={fmt(skillsWithScripts)}
            sub={`${scriptPct} of catalog`}
            accent={skillsWithScripts > 0 ? "negative" : "positive"}
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

      {/* Risk Level Breakdown */}
      <div>
        <SectionTitle sub="How scanned skills are rated across all risk levels">
          Risk Level Breakdown
        </SectionTitle>
        <div className="space-y-2">
          {riskSorted.map((r) => {
            const pct =
              totalRiskScanned > 0 ? (r.cnt / totalRiskScanned) * 100 : 0;
            return (
              <div key={r.level} className="flex items-center gap-3">
                <div
                  className="text-[11px] font-mono font-semibold text-right"
                  style={{ width: 72, color: RISK_COLORS[r.level] ?? "#555" }}
                >
                  {r.level}
                </div>
                <div
                  className="flex-1 bg-[#eee9d7] rounded-sm overflow-hidden"
                  style={{ height: 18 }}
                >
                  <div
                    style={{
                      width: `${pct.toFixed(1)}%`,
                      background: RISK_COLORS[r.level] ?? "#aaa",
                      height: "100%",
                      minWidth: pct > 0.3 ? 4 : 0,
                    }}
                  />
                </div>
                <div
                  className="text-[11px] font-mono text-[#474747]"
                  style={{ width: 100 }}
                >
                  {fmt(r.cnt)} ({pct.toFixed(1)}%)
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Findings by Threat Category */}
      {findingsCats.length > 0 && (
        <div>
          <SectionTitle sub="Breakdown of all security findings by threat type">
            Threat Intelligence
          </SectionTitle>
          <ResponsiveContainer width="100%" height={210}>
            <BarChart
              data={findingsCats}
              layout="vertical"
              margin={{
                top: 4,
                right: isMobile ? 8 : 80,
                bottom: 4,
                left: isMobile ? 0 : 160,
              }}
            >
              <CartesianGrid
                strokeDasharray="3 3"
                stroke="#e4e0d6"
                horizontal={false}
              />
              <XAxis
                type="number"
                tick={{ fontSize: 11, fontFamily: "IBM Plex Mono" }}
                tickFormatter={(v) => v.toLocaleString()}
              />
              <YAxis
                type="category"
                dataKey="name"
                tick={{
                  fontSize: isMobile ? 10 : 11,
                  fontFamily: "IBM Plex Mono",
                }}
                width={isMobile ? 90 : 158}
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
              <Bar dataKey="cnt" radius={[0, 2, 2, 0]}>
                {findingsCats.map((_, i) => (
                  <Cell
                    key={i}
                    fill={THREAT_COLORS[i % THREAT_COLORS.length]}
                  />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Category Distribution */}
      <div>
        <SectionTitle sub="Top 20 skill categories by count">
          Category Distribution
        </SectionTitle>
        <ResponsiveContainer width="100%" height={360}>
          <BarChart
            data={categories}
            layout="vertical"
            margin={{
              top: 4,
              right: isMobile ? 8 : 60,
              bottom: 4,
              left: isMobile ? 0 : 140,
            }}
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
              tick={{
                fontSize: isMobile ? 10 : 11,
                fontFamily: "IBM Plex Mono",
              }}
              width={isMobile ? 90 : 138}
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

      {/* Category Risk Ratios */}
      {catRisk.length > 0 && (
        <div>
          <SectionTitle sub="% of skills rated HIGH or CRITICAL per category (categories with ≥ 30 skills)">
            Category Risk Ratios
          </SectionTitle>
          <ResponsiveContainer width="100%" height={360}>
            <BarChart
              data={catRisk}
              layout="vertical"
              margin={{
                top: 4,
                right: isMobile ? 8 : 60,
                bottom: 4,
                left: isMobile ? 0 : 160,
              }}
            >
              <CartesianGrid
                strokeDasharray="3 3"
                stroke="#e4e0d6"
                horizontal={false}
              />
              <XAxis
                type="number"
                domain={[0, 100]}
                tickFormatter={(v) => `${v}%`}
                tick={{ fontSize: 11, fontFamily: "IBM Plex Mono" }}
              />
              <YAxis
                type="category"
                dataKey="name"
                tick={{
                  fontSize: isMobile ? 10 : 11,
                  fontFamily: "IBM Plex Mono",
                }}
                width={isMobile ? 90 : 158}
              />
              <Tooltip
                contentStyle={{
                  background: "#fbf7eb",
                  borderColor: "#393939",
                  fontFamily: "IBM Plex Mono",
                  fontSize: 12,
                }}
                formatter={(v, _n, p) => [
                  `${v}%  (${p.payload.risky} / ${p.payload.total} skills)`,
                  "HIGH + CRITICAL",
                ]}
              />
              <Bar dataKey="risky_pct" radius={[0, 2, 2, 0]}>
                {catRisk.map((c) => (
                  <Cell
                    key={c.name}
                    fill={
                      c.risky_pct >= 60
                        ? RISK_COLORS.CRITICAL
                        : c.risky_pct >= 40
                          ? RISK_COLORS.HIGH
                          : c.risky_pct >= 20
                            ? RISK_COLORS.MEDIUM
                            : RISK_COLORS.CLEAN
                    }
                  />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Metadata Quality */}
      <div>
        <SectionTitle sub="Completeness and freshness of skill metadata">
          Metadata Quality
        </SectionTitle>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
          <MetricCard
            label="No Description"
            value={noDescPct}
            sub={`${fmt(noDescCount)} skills lack a description`}
            accent={noDescCount > 0 ? "negative" : "positive"}
          />
          <MetricCard
            label="No Version Tag"
            value={noVersionPct}
            sub={`${fmt(noVersionCount)} skills unpinned`}
            accent={noVersionCount > active * 0.5 ? "negative" : "neutral"}
          />
          <MetricCard
            label="Zero-size Skills"
            value={fmt(zeroSizeCount)}
            sub="empty or missing folders"
            accent={zeroSizeCount > 0 ? "negative" : "positive"}
          />
          <MetricCard
            label="Peak Growth Day"
            value={peakDay ? fmt(peakDay.added) : "—"}
            sub={peakDay ? `skills on ${peakDay.month}` : "no data"}
          />
        </div>
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
                → Catalog totals <strong>{fmtSize(totalSizeBytes)}</strong> of
                skill content across <strong>{fmt(totalFiles)}</strong> files
              </li>
              <li>
                → <strong>{fmt(totalMds)}</strong> Markdown docs (avg{" "}
                <strong>
                  {active > 0 ? (totalMds / active).toFixed(1) : 0}
                </strong>{" "}
                per skill)
              </li>
              <li>→ Top 3 domains: {top3Cats}</li>
              <li>
                →{" "}
                <strong>
                  {riskSorted.find((r) => r.level === "CLEAN")
                    ? fmt(riskSorted.find((r) => r.level === "CLEAN").cnt)
                    : "0"}
                </strong>{" "}
                skills scan CLEAN — no issues detected
              </li>
            </ul>
          </div>
          <div className="border border-dashed border-[#c6392c] p-4">
            <div className="text-[11px] uppercase tracking-wide text-[#c6392c] mb-2 font-semibold">
              Needs attention
            </div>
            <ul className="space-y-1.5 text-[12px] text-[#474747]">
              <li>
                → <strong>{highRisk}</strong> skills flagged HIGH or CRITICAL;
                scan coverage is only <strong>{scannedPct}</strong>
              </li>
              <li>
                → Supply chain attacks dominate threats — check the Threat
                Intelligence chart above
              </li>
              <li>
                → <strong>Blockchain &amp; Crypto</strong> and{" "}
                <strong>API Integration</strong> categories have the highest
                share of risky skills (≥ 60%)
              </li>
              <li>
                → <strong>{noVersionPct}</strong> of skills (
                {fmt(noVersionCount)}) have no version tag — dependency pinning
                is minimal
              </li>
              <li>
                → <strong>{noDescPct}</strong> of skills ({fmt(noDescCount)})
                lack a description — discoverability suffers
              </li>
              <li>
                → <strong>{fmt(skillsWithScripts)}</strong> skills ({scriptPct})
                contain executable scripts (sh/py) — review for malicious code
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
