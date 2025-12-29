export default function AppFooter() {
  return (
    <footer className="border-t border-slate-200 bg-white px-4 py-3 text-xs text-slate-500">
      <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
        <div>© {new Date().getFullYear()} Coagro Internacional · Taller</div>
  
        <div className="flex items-center gap-3">
          <span className="rounded-md bg-slate-100 px-2 py-1 text-[11px] text-slate-600">
            v1.0
          </span>
          <span className="text-slate-300">|</span>
          <span className="text-[11px]">TI 👨‍💻 DESARROLLADOR WEB </span>
        </div>
      </div>
    </footer>
  );
}