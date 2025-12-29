import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { authFetch } from "../api/client";
import NuevoEquipoModal from "../components/NuevoEquipoModal";
import { useToast } from "../ui/toast/ToastProvider";

type Orden = {
  id: number;
  codigo: string;
  estado: string;
  cliente: { nombre: string } | null;
  equipo: { marca: string; modelo: string } | null;
  fechaIngreso: string;
};

export default function OrdersPage() {
  const navigate = useNavigate();
  const toast = useToast();

  const [openNuevoEquipo, setOpenNuevoEquipo] = useState(false);
  const [ordenes, setOrdenes] = useState<Orden[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchOrdenes = async () => {
    try {
      setLoading(true);
      const data = await authFetch("/api/ordenes");
      setOrdenes(data);
    } catch (err: any) {
      console.error("Error cargando órdenes:", err);
      toast.error(err?.message || "No se pudieron cargar las órdenes", "Error");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {   
    fetchOrdenes();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const badgeEstado = (estado: string) => {
    // versión simple: mismo color, pero queda centralizado para mejorar después
    return (
      <span className="rounded bg-emerald-100 px-2 py-1 text-xs font-semibold text-emerald-700">
        {estado}
      </span>
    );
  };

  return (
    <>
      {/* Título + botón registrar maquinaria */}
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-slate-800">
            Órdenes de servicio
          </h1>
          <p className="text-xs text-slate-500">
            Vista global · luego metemos filtros por sede/estado/técnico.
          </p>
        </div>

        <button
          onClick={() => setOpenNuevoEquipo(true)}
          className="rounded-lg bg-emerald-500 px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-emerald-600"
        >
          + Registrar maquinaria
        </button>
      </div>

      {/* Loading */}
      {loading && (
        <div className="text-center text-slate-600">Cargando órdenes...</div>
      )}

      {/* Empty state */}
      {!loading && ordenes.length === 0 && (
        <div className="rounded-xl bg-white p-10 text-center shadow">
          <p className="text-slate-600">No hay órdenes registradas aún.</p>
        </div>
      )}

      {/* Tabla de órdenes */}
      {!loading && ordenes.length > 0 && (
        <div className="overflow-hidden rounded-xl bg-white shadow">
          <table className="min-w-full text-sm">
            <thead className="bg-slate-100 text-slate-700">
              <tr>
                <th className="px-4 py-3 text-left">Código</th>
                <th className="px-4 py-3 text-left">Cliente</th>
                <th className="px-4 py-3 text-left">Equipo</th>
                <th className="px-4 py-3 text-left">Estado</th>
                <th className="px-4 py-3 text-left">Fecha ingreso</th>
                <th className="px-4 py-3 text-right">Acciones</th>
              </tr>
            </thead>

            <tbody>
              {ordenes.map((o) => (
                <tr
                  key={o.id}
                  className="border-t border-slate-200 hover:bg-slate-50"
                >
                  <td className="px-4 py-3 font-medium">{o.codigo}</td>
                  <td className="px-4 py-3">{o.cliente?.nombre || "-"}</td>
                  <td className="px-4 py-3">
                    {o.equipo ? `${o.equipo.marca} ${o.equipo.modelo}` : "-"}
                  </td>
                  <td className="px-4 py-3">{badgeEstado(o.estado)}</td>
                  <td className="px-4 py-3">
                    {new Date(o.fechaIngreso).toLocaleString()}
                  </td>

                  <td className="px-4 py-3 text-right">
                    <button
                      onClick={() => navigate(`/ordenes/${o.id}`)}
                      className="rounded-lg border border-slate-300 px-3 py-1.5 text-xs font-semibold text-slate-700 hover:bg-slate-100"
                    >
                      Ver detalle
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Modal para registrar maquinaria */}
      <NuevoEquipoModal
        open={openNuevoEquipo}
        onClose={() => setOpenNuevoEquipo(false)}
        onCreated={() => {
          setOpenNuevoEquipo(false);
          toast.success("Equipo registrado", "Listo");
          // Si quieres, aquí puedes redirigir a /equipos o refrescar equipos.
          // fetchOrdenes(); // (solo si en el futuro registrar equipo también crea orden)
        }}
      />    
    </>
  );
}
