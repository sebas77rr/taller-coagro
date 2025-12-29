import { useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { authFetch } from "../api/client";
import { useToast } from "../ui/toast/ToastProvider";

type Orden = any;

export default function OrderPrintPage() {
  const { id } = useParams();
  const ordenId = Number(id);
  const toast = useToast();
  const navigate = useNavigate();

  const [orden, setOrden] = useState<Orden | null>(null);
  const [loading, setLoading] = useState(true);

  const fechaIngreso = useMemo(() => {
    if (!orden?.fechaIngreso) return "";
    return new Date(orden.fechaIngreso).toLocaleString();
  }, [orden?.fechaIngreso]);

  const fechaSalida = useMemo(() => {
    if (!orden?.fechaSalida) return "";
    return new Date(orden.fechaSalida).toLocaleString();
  }, [orden?.fechaSalida]);

  useEffect(() => {
    if (!ordenId || Number.isNaN(ordenId)) {
      toast.error("ID inválido", "Error");
      navigate("/", { replace: true });
      return;
    }

    (async () => {
      try {
        setLoading(true);
        const data = await authFetch(`/api/ordenes/${ordenId}`);
        setOrden(data);

        // Auto-print opcional:
        // setTimeout(() => window.print(), 350);
      } catch (e: any) {
        console.error(e);
        toast.error(e?.message || "No se pudo cargar la orden", "Error");
      } finally {
        setLoading(false);
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ordenId]);

  if (loading) {
    return (
      <div className="rounded-xl border border-slate-200 bg-white p-6 text-sm text-slate-600">
        Cargando para impresión...
      </div>
    );
  }

  if (!orden) {
    return (
      <div className="rounded-xl border border-slate-200 bg-white p-6 text-sm text-slate-600">
        No se encontró la orden.
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-3xl space-y-4">
      {/* CSS impresión */}
      <style>
        {`
          @media print {
            .no-print { display: none !important; }
            body { background: white !important; }
          }
        `}
      </style>

      {/* Acciones (no se imprimen) */}
      <div className="no-print flex items-center justify-between">
        <button
          onClick={() => navigate(-1)}
          className="rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm font-semibold text-slate-700 hover:bg-slate-100"
        >
          ← Volver
        </button>

        <button
          onClick={() => window.print()}
          className="rounded-lg bg-slate-900 px-4 py-2 text-sm font-semibold text-white hover:bg-slate-800"
        >
          Imprimir / Guardar PDF
        </button>
      </div>

      {/* Documento */}
      <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
        <div className="flex items-start justify-between gap-4">
          <div>
            <div className="text-xs font-semibold uppercase text-slate-500">
              Taller Coagro · Orden de servicio
            </div>
            <div className="mt-1 text-2xl font-semibold text-slate-900">
              {orden.codigo}
            </div>

            <div className="mt-2 text-sm text-slate-700">
              <div><span className="font-semibold">Estado:</span> {orden.estado}</div>
              <div><span className="font-semibold">Fecha ingreso:</span> {fechaIngreso}</div>
              {orden.fechaSalida && (
                <div><span className="font-semibold">Fecha salida:</span> {fechaSalida}</div>
              )}
            </div>
          </div>

          <div className="text-right text-sm text-slate-700">
            <div className="font-semibold">{orden.sede?.nombre}</div>
            <div className="text-slate-600">{orden.sede?.ciudad}</div>
            <div className="mt-2">
              <span className="font-semibold">Tipo:</span> {orden.tipoIngreso}
            </div>
          </div>
        </div>

        <hr className="my-4 border-slate-200" />

        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          <div className="rounded-xl border border-slate-200 p-4">
            <div className="text-xs font-semibold uppercase text-slate-500">Cliente</div>
            <div className="mt-1 text-sm font-semibold text-slate-900">
              {orden.cliente?.nombre}
            </div>
            <div className="text-sm text-slate-700">
              {orden.cliente?.empresa ? `Empresa: ${orden.cliente.empresa}` : ""}
            </div>
          </div>

          <div className="rounded-xl border border-slate-200 p-4">
            <div className="text-xs font-semibold uppercase text-slate-500">Equipo</div>
            <div className="mt-1 text-sm font-semibold text-slate-900">
              {orden.equipo?.marca} {orden.equipo?.modelo}
            </div>
            <div className="text-sm text-slate-700">
              Serial: {orden.equipo?.serial}
            </div>
          </div>
        </div>

        <div className="mt-4 rounded-xl border border-slate-200 p-4">
          <div className="text-xs font-semibold uppercase text-slate-500">Motivo de ingreso</div>
          <div className="mt-1 text-sm text-slate-800">{orden.motivoIngreso}</div>
        </div>

        <div className="mt-4 grid grid-cols-1 gap-4 md:grid-cols-2">
          <div className="rounded-xl border border-slate-200 p-4">
            <div className="mb-2 text-xs font-semibold uppercase text-slate-500">Mano de obra</div>
            {(orden.manoObra?.length ?? 0) === 0 ? (
              <div className="text-sm text-slate-500">Sin registros</div>
            ) : (
              <ul className="space-y-2 text-sm">
                {orden.manoObra.map((m: any) => (
                  <li key={m.id} className="rounded-lg border border-slate-200 p-2">
                    <div className="font-semibold text-slate-900">
                      {m.descripcionTrabajo || m.descripcion || "Trabajo"}
                    </div>
                    <div className="text-slate-600">Horas: {m.horas}</div>
                  </li>
                ))}
              </ul>
            )}
          </div>

          <div className="rounded-xl border border-slate-200 p-4">
            <div className="mb-2 text-xs font-semibold uppercase text-slate-500">Repuestos</div>
            {(orden.repuestos?.length ?? 0) === 0 ? (
              <div className="text-sm text-slate-500">Sin repuestos</div>
            ) : (
              <ul className="space-y-2 text-sm">
                {orden.repuestos.map((r: any) => (
                  <li key={r.id} className="rounded-lg border border-slate-200 p-2">
                    <div className="font-semibold text-slate-900">
                      {r.repuesto?.codigo ? `${r.repuesto.codigo} · ` : ""}
                      {r.repuesto?.descripcion || "Repuesto"}
                    </div>
                    <div className="text-slate-600">Cantidad: {r.cantidad}</div>
                  </li>
                ))}
              </ul>
            )}    
          </div>
        </div>

        {/* Firmas (pro) */}
        <div className="mt-6 grid grid-cols-1 gap-6 md:grid-cols-2">
          <div>
            <div className="text-xs font-semibold uppercase text-slate-500">Firma cliente</div>
            <div className="mt-8 border-t border-slate-300 pt-2 text-sm text-slate-600">
              Nombre / CC
            </div>
          </div>
          <div>
            <div className="text-xs font-semibold uppercase text-slate-500">Firma taller</div>
            <div className="mt-8 border-t border-slate-300 pt-2 text-sm text-slate-600">
              Técnico / Responsable
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}    