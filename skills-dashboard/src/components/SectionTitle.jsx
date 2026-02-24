export function SectionTitle({ children, sub }) {
  return (
    <div className="mb-4">
      <h2 className="text-sm font-bold uppercase tracking-widest text-[#141414]">{children}</h2>
      {sub && <p className="text-[11px] text-[#6b6b6b] mt-0.5">{sub}</p>}
      <div className="mt-1 border-b border-dashed border-[#393939]" />
    </div>
  )
}
