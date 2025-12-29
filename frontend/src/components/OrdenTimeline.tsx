import { useEffect, useState } from "react";
import { authFetch } from "../api/client";
import { useToast } from "../ui/toast/ToastProvider";

type Evento = {
  id: number;
  tipo: string;
  detalle?: string | null;      
  createdAt: string;   
  usuarioId?: number | null;
};

function etiqueta(tipo: string) {
  switch (tipo) {
    case "ORDEN_CREADA":
      return { text: "Creación", cls: "bg-sky-100 text-sky-700" };
    case "ESTADO_CAMBIADO":
      return { text: "Estado", cls: "bg-amber-100 text-amber-800" };
    case "TECNICO_ASIGNADO":
      return { text: "Técnico", cls: "bg-violet-100 text-violet-800" };
    case "MANO_OBRA_AGREGADA":
      return { text: "Mano de obra", cls: "bg-emerald-100 text-emerald-800" };
    case "REPUESTO_AGREGADO":
      return { text: "Repuesto", cls: "bg-slate-100 text-slate-700" };
    default:
      return { text: tipo, cls: "bg-slate-100 text-slate-700" };
  }
}

export default function OrdenTimeline({
  ordenId,
  refreshKey,
}: {
  ordenId: number;
  refreshKey?: number;
}) {
  const toast = useToast();
  const [eventos, setEventos] = useState<Evento[]>([]);
  const [loading, setLoading] = useState(true);

  const cargar = async () => {
    try {
      setLoading(true);
      const data = await authFetch(`/api/ordenes/${ordenId}/eventos`);
      setEventos(data);
    } catch (e: any) {
      console.error(e);
      toast.error("No se pudo cargar la actividad", "Error");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (!ordenId) return;
    cargar();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ordenId, refreshKey]);

  return (
    <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
      <div className="flex items-center justify-between">
        <div className="text-sm font-semibold text-slate-900">Actividad</div>
        <button
          onClick={cargar}
          className="rounded-lg border border-slate-300 px-3 py-1.5 text-xs font-semibold text-slate-700 hover:bg-slate-100"
          type="button"
        >
          Refrescar
        </button>
      </div>

      <div className="mt-4">
        {loading && <div className="text-sm text-slate-500">Cargando actividad...</div>}

        {!loading && eventos.length === 0 && (
          <div className="text-sm text-slate-500">Aún no hay eventos.</div>
        )}

        {!loading && eventos.length > 0 && (
          <ul className="space-y-3">
            {eventos.map((ev) => {
              const tag = etiqueta(ev.tipo);
              return (
                <li key={ev.id} className="rounded-xl border border-slate-200 p-3">
                  <div className="flex items-start justify-between gap-3">
                    <span className={`inline-flex rounded-full px-2 py-1 text-[11px] font-semibold ${tag.cls}`}>
                      {tag.text}
                    </span>
                    <div className="text-[11px] text-slate-500">
                      {new Date(ev.createdAt).toLocaleString()}
                    </div>
                  </div>

                  {ev.detalle && (
                    <div className="mt-2 text-sm text-slate-800">{ev.detalle}</div>
                  )}

                  <div className="mt-2 text-[11px] text-slate-500">
                    Usuario: {ev.usuarioId ?? "—"}
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </div>
  );
}       