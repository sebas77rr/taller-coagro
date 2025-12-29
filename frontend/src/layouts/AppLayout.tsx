import { Outlet, useLocation, useNavigate } from "react-router-dom";
import { getUsuario, logout } from "../hooks/useAuth";
import AppFooter from "../components/AppFooter";

function Tile({
  title,
  desc,
  icon,
  path,
}: {
  title: string;
  desc: string;
  icon: string;
  path: string;
}) {
  const navigate = useNavigate();
  const location = useLocation();
  const active = location.pathname === path;

  return (
    <button
      onClick={() => navigate(path)}
      className={[
        "group w-full rounded-2xl border bg-white p-4 text-left shadow-sm transition",
        "hover:-translate-y-0.5 hover:shadow-md",
        "focus:outline-none focus:ring-2 focus:ring-emerald-500",
        active
          ? "border-emerald-300 ring-1 ring-emerald-200"
          : "border-slate-200",
      ].join(" ")}
    >
      <div className="flex items-start gap-3">
        <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-slate-900 text-white">
          <span className="text-lg">{icon}</span>
        </div>

        <div className="min-w-0 flex-1">
          <div className="flex items-center justify-between">
            <div className="text-sm font-semibold text-slate-900">{title}</div>
            <div className="text-xs text-slate-400 transition group-hover:translate-x-0.5">
              →
            </div>
          </div>
          <div className="mt-1 text-xs text-slate-500">{desc}</div>
        </div>
      </div>
    </button>
  );
}

export default function AppLayout() {
  const usuario = getUsuario();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate("/login", { replace: true });
  };

  return (
    <div className="min-h-screen bg-slate-100 flex flex-col">
      {/* Header */}
      <header className="h-14 bg-slate-900 text-white flex items-center justify-between px-4 shadow">
        <div className="flex items-center gap-2">
          <div className="h-8 w-8 rounded-lg bg-emerald-500 flex items-center justify-center text-xs font-bold">
            TC
          </div>
          <div className="leading-tight">
            <p className="text-[11px] uppercase text-slate-300">
              Taller Coagro
            </p>
            <p className="text-xs">
              Módulo de taller{" "}
              {usuario?.sedeId ? `· Sede #${usuario.sedeId}` : ""}
            </p>
          </div>
        </div>

        {usuario && (
          <div className="flex items-center gap-3">
            <div className="text-right leading-tight">
              <p className="text-xs font-medium">{usuario.nombre}</p>
              <p className="text-[11px] text-slate-300">
                {usuario.rol} · {usuario.email}
              </p>
            </div>
            <button
              onClick={handleLogout}
              className="text-[11px] border border-slate-500/70 px-2 py-1 rounded-md hover:bg-slate-800 transition"
            >
              Cerrar sesión
            </button>
          </div>
        )}
      </header>

      {/* Contenido */}
      <main className="flex-1 p-4">
        {/* Accesos rápidos enterprise */}
        <div className="mb-4">
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
            <Tile
              title="Órdenes"  
              desc="Gestiona órdenes, estados y seguimiento"
              icon="📋"
              path="/"
            />
            <Tile
              title="Equipos"
              desc="Registrar maquinaria y crear órdenes"  
              icon="🛠️"
              path="/equipos"     
            />
          </div>
        </div>

        <Outlet />
      </main>
      <AppFooter />
    </div>
  );
}
