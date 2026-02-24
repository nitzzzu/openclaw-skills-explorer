import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";
import { SectionTitle } from "../components/SectionTitle";

const PALETTE = [
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
  "#d2836e",
  "#4a9a8a",
  "#4a5568",
  "#d4a843",
  "#7b68ee",
];

export function AuthorsSection({ data }) {
  const { authors } = data;
  const topAuthor = authors[0];
  const totalTopAuthors = authors.slice(0, 10).reduce((a, r) => a + r.cnt, 0);

  return (
    <div className="space-y-8">
      <div>
        <SectionTitle sub="Top 25 authors ranked by skill count">
          Top Skill Authors
        </SectionTitle>

        <div className="flex flex-wrap gap-4 mb-6">
          <div className="border border-dashed border-[#393939] px-4 py-2">
            <div className="text-[10px] text-[#6b6b6b] uppercase">
              Top Author
            </div>
            <div className="text-xl font-bold">{topAuthor?.author}</div>
            <div className="text-[11px] text-[#9e9e9e]">
              {topAuthor?.cnt.toLocaleString()} skills
            </div>
          </div>
          <div className="border border-dashed border-[#393939] px-4 py-2">
            <div className="text-[10px] text-[#6b6b6b] uppercase">
              Top 10 Combined
            </div>
            <div className="text-xl font-bold">
              {totalTopAuthors.toLocaleString()}
            </div>
            <div className="text-[11px] text-[#9e9e9e]">
              skills from 10 authors
            </div>
          </div>
        </div>

        <ResponsiveContainer width="100%" height={420}>
          <BarChart
            data={authors}
            layout="vertical"
            margin={{ top: 4, right: 60, bottom: 4, left: 130 }}
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
              dataKey="author"
              tick={{ fontSize: 11, fontFamily: "IBM Plex Mono" }}
              width={128}
            />
            <Tooltip
              contentStyle={{
                background: "#fbf7eb",
                borderColor: "#393939",
                fontFamily: "IBM Plex Mono",
                fontSize: 12,
              }}
              formatter={(v, n, p) => [
                v.toLocaleString() + " skills",
                p.payload.author,
              ]}
            />
            <Bar dataKey="cnt" radius={[0, 2, 2, 0]}>
              {authors.map((_, i) => (
                <Cell key={i} fill={PALETTE[i % PALETTE.length]} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>

      {/* Author table */}
      <div>
        <SectionTitle sub="Ranked leaderboard">
          Authors Leaderboard
        </SectionTitle>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
          {authors.slice(0, 20).map((a, i) => (
            <div
              key={a.author}
              className="flex items-center justify-between border-b border-dashed border-[#e4e0d6] py-1.5"
            >
              <div className="flex items-center gap-3">
                <span className="text-[11px] text-[#9e9e9e] w-6 tabular-nums">
                  {i + 1}
                </span>
                <span className="text-[12px] font-mono text-[#3b6fd4]">
                  {a.author}
                </span>
              </div>
              <div className="flex items-center gap-2">
                <div className="h-1.5 bg-[#e4e0d6] rounded-sm overflow-hidden w-16">
                  <div
                    className="h-full"
                    style={{
                      width: `${(a.cnt / authors[0].cnt) * 100}%`,
                      background: PALETTE[i % PALETTE.length],
                    }}
                  />
                </div>
                <span className="text-[12px] font-semibold tabular-nums w-10 text-right">
                  {a.cnt}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
