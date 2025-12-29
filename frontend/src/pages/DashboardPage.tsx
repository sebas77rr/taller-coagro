import { useEffect, useState } from "react";
import { getToken, getUsuario } from "../hooks/useAuth";

type Orden = {
  id: number;
  codigo: string;
  estado: string;
  tipoIngreso: string;
  fechaIngreso: string;
  sede?: { nombre: string };
  cliente?: { nombre: string };
};

export default function DashboardPage() {
  const [ordenes, setOrdenes] = useState<Orden[]>([]);
  const [cargando, setCargando] = useState(true);
  const [error, setError] = useState("");
  const usuario = getUsuario();

  useEffect(() => {
    const fetchData = async () => {
      try {
        setError("");
        setCargando(true);

        const token = getToken();
        const params = new URLSearchParams();

        // Filtro automático por sede si el usuario tiene sede
        if (usuario?.sedeId) {
          params.append("sedeId", String(usuario.sedeId));
        }

        const res = await fetch(
          `http://localhost:4000/api/ordenes?${params.toString()}`,
          {
            headers: {
              "Content-Type": "application/json",
              Authorization: token ? `Bearer ${token}` : "",
            },
          }
        );

        const data = await res.json();

        if (!res.ok) {
          setError(data.error || "Error cargando órdenes");
          return;
        }

        setOrdenes(data);
      } catch (err) {
        console.error(err);
        setError("No se pudo conectar con el servidor");
      } finally {
        setCargando(false);
      }
    };

    fetchData();
  }, [usuario?.sedeId]);

  return (
    <div className="max-w-6xl mx-auto space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-slate-900">
            Órdenes de servicio
          </h1>
          <p className="text-xs text-slate-500">
            {usuario?.rol === "ADMIN"
              ? "Vista global · puedes filtrar por sede después."
              : "Ves únicamente las órdenes de tu sede."}
          </p>
        </div>
      </div>

      {cargando && (
        <div className="text-xs text-slate-500">Cargando órdenes...</div>
      )}

      {error && (
        <div className="text-xs text-red-700 bg-red-50 border border-red-200 rounded-lg px-3 py-2">
          {error}
        </div>
      )}

      {!cargando && !error && (
        <div className="bg-white rounded-xl shadow-sm border border-slate-200 overflow-hidden">
          <table className="w-full text-xs">
            <thead className="bg-slate-50 border-b border-slate-200">
              <tr>
                <th className="text-left px-3 py-2">Código</th>
                <th className="text-left px-3 py-2">Cliente</th>
                <th className="text-left px-3 py-2">Sede</th>
                <th className="text-left px-3 py-2">Tipo</th>
                <th className="text-left px-3 py-2">Estado</th>
                <th className="text-left px-3 py-2">Ingreso</th>
              </tr>
            </thead>
            <tbody>
              {ordenes.length === 0 && (
                <tr>
                  <td
                    colSpan={6}
                    className="px-3 py-4 text-center text-slate-400"
                  >
                    No hay órdenes registradas todavía.
                  </td>
                </tr>
              )}

              {ordenes.map((o) => (
                <tr
                  key={o.id}
                  className="border-b border-slate-100 hover:bg-slate-50/80"
                >
                  <td className="px-3 py-2 font-mono text-[11px]">
                    {o.codigo}
                  </td>
                  <td className="px-3 py-2">{o.cliente?.nombre ?? "-"}</td>
                  <td className="px-3 py-2">{o.sede?.nombre ?? "-"}</td>
                  <td className="px-3 py-2 text-[11px]">{o.tipoIngreso}</td>
                  <td className="px-3 py-2">
                    <span className="inline-flex items-center px-2 py-[2px] rounded-full text-[10px] bg-emerald-50 text-emerald-700 border border-emerald-100">
                      {o.estado}
                    </span>
                  </td>
                  <td className="px-3 py-2 text-[11px] text-slate-500">
                    {new Date(o.fechaIngreso).toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}   