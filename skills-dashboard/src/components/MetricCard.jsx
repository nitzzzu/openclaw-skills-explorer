export function MetricCard({ label, value, sub, accent }) {
  const accentStyle = accent
    ? { color: accent === 'positive' ? '#2f7d31' : accent === 'negative' ? '#c6392c' : '#b45309' }
    : {}

  return (
    <div className="flex flex-col gap-0.5 py-3 px-3 border border-dashed border-[#393939]">
      <div className="text-[11px] text-[#6b6b6b] uppercase tracking-wide">{label}</div>
      <div className="text-2xl font-bold" style={accentStyle}>{value}</div>
      {sub && <div className="text-[11px] text-[#9e9e9e]">{sub}</div>}
    </div>
  )
}
