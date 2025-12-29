import { useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { authFetch } from "../api/client";
import { useToast } from "../ui/toast/ToastProvider";
import AgregarManoObraModal from "../components/AgregarManoObraModal";
import AgregarRepuestoModal from "../components/AgregarRepuestoModal";
import OrdenTimeline from "../components/OrdenTimeline";
import EditarManoObraModal from "../components/EditarManoObraModal";

type Orden = any;

type Tecnico = {
  id: number;
  nombre: string;
  email: string;
  sedeId: number | null;
};

const estadosValidos = [
  "ABIERTA",
  "EN_PROCESO",
  "ESPERANDO_REPUESTO",
  "FINALIZADA",
  "ENTREGADA",
] as const;

export default function OrderDetailPage() {
  const { id } = useParams();
  const ordenId = Number(id);

  const toast = useToast();
  const navigate = useNavigate();

  const [orden, setOrden] = useState<Orden | null>(null);
  const [loading, setLoading] = useState(true);

  const [savingEstado, setSavingEstado] = useState(false);
  const [closing, setClosing] = useState(false);

  const [openManoObra, setOpenManoObra] = useState(false);
  const [openRepuesto, setOpenRepuesto] = useState(false);

  // ✅ Editar mano de obra
  const [editingManoObra, setEditingManoObra] = useState<any | null>(null);
  const [openEditarManoObra, setOpenEditarManoObra] = useState(false);

  const [editingRepuesto, setEditingRepuesto] = useState<any | null>(null);
  const [openEditarRepuesto, setOpenEditarRepuesto] = useState(false);

  // ✅ Técnicos
  const [tecnicos, setTecnicos] = useState<Tecnico[]>([]);
  const [savingTecnico, setSavingTecnico] = useState(false);

  // ✅ Timeline refresh
  const [timelineKey, setTimelineKey] = useState(0);
  const refreshTimeline = () => setTimelineKey((k) => k + 1);

  const esCerrada = useMemo(() => {
    const st = orden?.estado;
    return st === "FINALIZADA" || st === "ENTREGADA";
  }, [orden?.estado]);

  const cargar = async () => {
    try {
      setLoading(true);
      const data = await authFetch(`/api/ordenes/${ordenId}`);
      setOrden(data);
    } catch (e: any) {
      console.error(e);
      toast.error(e?.message || "No se pudo cargar la orden", "Error");
    } finally {
      setLoading(false);
    }
  };

  const cargarTecnicos = async () => {
    try {
      const data = await authFetch("/api/tecnicos");
      setTecnicos(data || []);
    } catch (e: any) {
      console.error(e);
      toast.warning("No se pudieron cargar los técnicos", "Aviso");
    }
  };

  useEffect(() => {
    if (!ordenId || Number.isNaN(ordenId)) {
      toast.error("ID de orden inválido", "Error");
      navigate("/", { replace: true });
      return;
    }
    cargar();
    cargarTecnicos();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ordenId]);

  const cambiarEstado = async (estado: string) => {
    if (!orden) return;

    if (esCerrada) {
      toast.info("Esta orden ya está cerrada", "Solo lectura");
      return;
    }

    try {
      setSavingEstado(true);
      const upd = await authFetch(`/api/ordenes/${orden.id}/estado`, {
        method: "PATCH",
        body: JSON.stringify({ estado }),
      });

      setOrden((prev: any) => ({ ...prev, ...upd }));
      toast.success("Estado actualizado", estado);
      refreshTimeline();
    } catch (e: any) {
      console.error(e);
      toast.error(e?.message || "No se pudo actualizar el estado", "Error");
    } finally {
      setSavingEstado(false);
    }
  };

  const asignarTecnico = async (tecnicoIdRaw: string) => {
    if (!orden) return;

    if (esCerrada) {
      toast.info("Orden cerrada", "No se puede reasignar");
      return;
    }

    try {
      setSavingTecnico(true);

      const payload = {
        tecnicoId: tecnicoIdRaw ? Number(tecnicoIdRaw) : null,
      };

      const upd = await authFetch(`/api/ordenes/${orden.id}/tecnico`, {
        method: "PATCH",
        body: JSON.stringify(payload),
      });

      setOrden((prev: any) => ({ ...prev, ...upd }));

      toast.success(
        "Técnico asignado",
        upd?.tecnicoAsignado?.nombre || "Sin asignar"
      );
      refreshTimeline();
    } catch (e: any) {
      console.error(e);
      toast.error(e?.message || "No se pudo asignar técnico", "Error");
    } finally {
      setSavingTecnico(false);
    }
  };

  const handleCerrarOrden = async () => {
    if (!orden) return;

    if (esCerrada) {
      toast.info("La orden ya está cerrada", "Nada que hacer");
      return;
    }

    const ok = window.confirm(
      `¿Seguro que quieres finalizar la orden ${orden.codigo}?\n\nDespués quedará en solo lectura.`
    );
    if (!ok) return;

    try {
      setClosing(true);

      const estado = "FINALIZADA";

      const upd = await authFetch(`/api/ordenes/${orden.id}/estado`, {
        method: "PATCH",
        body: JSON.stringify({ estado }),
      });

      setOrden((prev: any) => ({
        ...prev,
        ...upd,
        estado,
        fechaSalida: upd?.fechaSalida || new Date().toISOString(),
      }));

      toast.success("Orden finalizada", "Quedó en solo lectura");
      refreshTimeline();
    } catch (err: any) {
      console.error(err);
      toast.error(err?.message || "No se pudo cerrar la orden", "Error");
    } finally {
      setClosing(false);
    }
  };

  const eliminarManoObra = async (itemId: number) => {
    if (esCerrada) {
      toast.info("Orden cerrada", "Solo lectura");
      return;
    }

    const ok = window.confirm("¿Eliminar este registro de mano de obra?");
    if (!ok) return;

    try {
      await authFetch(`/api/ordenes/${orden.id}/mano-obra/${itemId}`, {
        method: "DELETE",
      });

      setOrden((prev: any) => ({
        ...prev,
        manoObra: (prev?.manoObra || []).filter((x: any) => x.id !== itemId),
      }));

      toast.success("Registro eliminado", "Mano de obra");
      refreshTimeline();
    } catch (e: any) {
      console.error(e);
      toast.error(e?.message || "No se pudo eliminar", "Error");
    }
  };

  const eliminarRepuesto = async (itemId: number) => {
    if (esCerrada) {
      toast.info("Orden cerrada", "Solo lectura");
      return;
    }

    const ok = window.confirm("¿Eliminar este repuesto de la orden?");
    if (!ok) return;

    try {
      await authFetch(`/api/ordenes/${orden.id}/repuestos/${itemId}`, {
        method: "DELETE",
      });

      setOrden((prev: any) => ({
        ...prev,
        repuestos: (prev?.repuestos || []).filter((x: any) => x.id !== itemId),
      }));

      toast.success("Repuesto eliminado", "Listo");
      refreshTimeline();
    } catch (e: any) {
      console.error(e);
      toast.error(e?.message || "No se pudo eliminar", "Error");
    }
  };

  if (loading) {
    return (
      <div className="rounded-xl border border-slate-200 bg-white p-6 text-sm text-slate-600">
        Cargando orden...
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
    <div className="space-y-4">
      {/* Header */}
      <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
        <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
          <div>
            <div className="text-xs font-semibold uppercase text-slate-500">
              Orden de servicio
            </div>

            <div className="mt-1 text-2xl font-semibold text-slate-900">
              {orden.codigo}
            </div>

            <div className="mt-2 text-sm text-slate-600">
              <span className="font-semibold">Cliente:</span>{" "}
              {orden.cliente?.nombre}
              {orden.cliente?.empresa ? ` · ${orden.cliente.empresa}` : ""}
              <span className="mx-2 text-slate-300">|</span>
              <span className="font-semibold">Equipo:</span>{" "}
              {orden.equipo?.marca} {orden.equipo?.modelo} · Serial:{" "}
              {orden.equipo?.serial}
            </div>

            <div className="mt-2 text-sm text-slate-600">
              <span className="font-semibold">Sede:</span> {orden.sede?.nombre}{" "}
              · {orden.sede?.ciudad}
              <span className="mx-2 text-slate-300">|</span>
              <span className="font-semibold">Ingreso:</span>{" "}
              {orden.tipoIngreso}
            </div>

            {orden.fechaSalida && (
              <div className="mt-2 text-sm text-slate-600">
                <span className="font-semibold">Salida:</span>{" "}
                {new Date(orden.fechaSalida).toLocaleString()}
              </div>
            )}

            {esCerrada && (
              <div className="mt-3 inline-flex items-center rounded-full bg-slate-100 px-3 py-1 text-xs font-semibold text-slate-700">
                ✅ Orden cerrada · Solo lectura
              </div>
            )}
          </div>

          <div className="flex flex-col gap-2">
            {/* Estado */}
            <div className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3">
              <div className="text-xs font-semibold uppercase text-slate-500">
                Estado
              </div>

              <div className="mt-1 flex items-center gap-2">
                <select
                  value={orden.estado}
                  onChange={(e) => cambiarEstado(e.target.value)}
                  disabled={savingEstado || esCerrada}
                  className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500 disabled:opacity-60"
                >
                  {estadosValidos.map((es) => (
                    <option key={es} value={es}>
                      {es}
                    </option>
                  ))}
                </select>
              </div>

              <div className="mt-2 text-xs text-slate-500">
                {savingEstado
                  ? "Actualizando..."
                  : esCerrada
                  ? "Orden cerrada: estado bloqueado"
                  : "Cambia el estado en tiempo real"}
              </div>
            </div>

            {/* Técnico */}
            <div className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3">
              <div className="text-xs font-semibold uppercase text-slate-500">
                Técnico asignado
              </div>

              <select
                value={orden.tecnicoId || ""}
                onChange={(e) => asignarTecnico(e.target.value)}
                disabled={savingTecnico || esCerrada}
                className="mt-2 w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500 disabled:opacity-60"
              >
                <option value="">Sin asignar</option>
                {tecnicos.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.nombre} {t.sedeId ? `· Sede #${t.sedeId}` : ""}
                  </option>
                ))}
              </select>

              <div className="mt-2 text-xs text-slate-500">
                {savingTecnico
                  ? "Asignando..."
                  : esCerrada
                  ? "Orden cerrada: no se puede reasignar"
                  : "Asigna el responsable del trabajo"}
              </div>

              {orden?.tecnicoAsignado?.nombre && (
                <div className="mt-2 text-xs text-slate-600">
                  Actual:{" "}
                  <span className="font-semibold text-slate-800">
                    {orden.tecnicoAsignado.nombre}
                  </span>
                </div>
              )}
            </div>

            {/* Cerrar orden */}
            <button
              type="button"
              onClick={handleCerrarOrden}
              disabled={closing || esCerrada}
              className="rounded-lg bg-slate-900 px-4 py-2 text-sm font-semibold text-white hover:bg-slate-800 disabled:opacity-60"
            >
              {closing ? "Cerrando..." : "Cerrar orden"}
            </button>

            <button
              onClick={() => navigate("/", { replace: true })}
              className="rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm font-semibold text-slate-700 hover:bg-slate-100"
            >
              ← Volver a Órdenes
            </button>

            <button
              type="button"
              onClick={() =>
                window.open(`/ordenes/${orden.id}/print`, "_blank")
              }
              className="rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm font-semibold text-slate-700 hover:bg-slate-100"
            >
              🖨️ Imprimir
            </button>
          </div>
        </div>

        <div className="mt-4 rounded-xl border border-slate-200 bg-white p-4">
          <div className="text-xs font-semibold uppercase text-slate-500">
            Motivo de ingreso
          </div>
          <div className="mt-1 text-sm text-slate-800">
            {orden.motivoIngreso}
          </div>
        </div>
      </div>

      {/* Secciones */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        {/* Mano de obra */}
        <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
          <div className="flex items-center justify-between">
            <div className="text-sm font-semibold text-slate-900">
              Mano de obra
            </div>
            <button
              className="rounded-lg border border-slate-300 px-3 py-1.5 text-xs font-semibold text-slate-700 hover:bg-slate-100 disabled:opacity-60"
              onClick={() => setOpenManoObra(true)}
              type="button"
              disabled={esCerrada}
              title={
                esCerrada
                  ? "Orden cerrada: no se puede editar"
                  : "Agregar mano de obra"
              }
            >
              + Agregar
            </button>
          </div>

          <div className="mt-3 text-sm text-slate-600">
            {(orden.manoObra?.length ?? 0) === 0 ? (
              <div className="text-slate-500">Aún no hay registros.</div>
            ) : (
              <ul className="space-y-2">
                {orden.manoObra.map((m: any) => (
                  <li
                    key={m.id}
                    className="rounded-lg border border-slate-200 p-3"
                  >
                    <div className="font-medium text-slate-900">
                      {m.descripcionTrabajo || m.descripcion || "Trabajo"}
                    </div>

                    <div className="text-xs text-slate-500">
                      Horas: {m.horas}
                    </div>

                    {!esCerrada && (
                      <div className="mt-2 flex gap-2">
                        <button
                          type="button"
                          className="rounded-md border border-slate-300 px-2 py-1 text-xs font-semibold hover:bg-slate-50"
                          onClick={() => {
                            setEditingManoObra(m);
                            setOpenEditarManoObra(true);
                          }}
                        >
                          Editar
                        </button>

                        <button
                          type="button"
                          className="rounded-md border border-red-200 px-2 py-1 text-xs font-semibold text-red-700 hover:bg-red-50"
                          onClick={() => eliminarManoObra(m.id)}
                        >
                          Eliminar
                        </button>
                      </div>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>

        {/* Repuestos */}
        <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
          <div className="flex items-center justify-between">
            <div className="text-sm font-semibold text-slate-900">
              Repuestos
            </div>
            <button
              className="rounded-lg border border-slate-300 px-3 py-1.5 text-xs font-semibold text-slate-700 hover:bg-slate-100 disabled:opacity-60"
              onClick={() => setOpenRepuesto(true)}
              type="button"
              disabled={esCerrada}
              title={
                esCerrada
                  ? "Orden cerrada: no se puede editar"
                  : "Agregar repuesto"
              }
            >
              + Agregar
            </button>
          </div>

          <div className="mt-3 text-sm text-slate-600">
            {(orden.repuestos?.length ?? 0) === 0 ? (
              <div className="text-slate-500">Aún no hay repuestos.</div>
            ) : (
              <ul className="space-y-2">
                {orden.repuestos.map((r: any) => (
                  <li
                    key={r.id}
                    className="rounded-lg border border-slate-200 p-3"
                  >
                    <div className="font-medium text-slate-900">
                      {r.repuesto?.descripcion || "Repuesto"}
                    </div>

                    <div className="text-xs text-slate-500">
                      Cantidad: {r.cantidad}
                      {typeof r.esGarantia === "boolean" && (
                        <>
                          <span className="mx-2 text-slate-300">|</span>
                          {r.esGarantia ? "Garantía" : "Normal"}
                        </>
                      )}
                    </div>
  
                    {!esCerrada && (
                      <div className="mt-2 flex gap-2">
                        <button
                          type="button"
                          className="rounded-md border border-slate-300 px-2 py-1 text-xs font-semibold hover:bg-slate-50"
                          onClick={() => {
                            setEditingRepuesto(r);
                            setOpenEditarRepuesto(true);
                          }}
                        >
                          Editar
                        </button>

                        <button
                          type="button"
                          className="rounded-md border border-red-200 px-2 py-1 text-xs font-semibold text-red-700 hover:bg-red-50"
                          onClick={() => eliminarRepuesto(r.id)}
                        >
                          Eliminar      
                        </button>
                      </div>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      </div>

      {/* ✅ Timeline */}
      <OrdenTimeline ordenId={orden.id} refreshKey={timelineKey} />

      {/* Modales */}
      <AgregarManoObraModal
        open={openManoObra}
        onClose={() => setOpenManoObra(false)}
        ordenId={orden.id}
        onCreated={(item) => {
          setOrden((prev: any) => ({
            ...prev,
            manoObra: [item, ...(prev?.manoObra || [])],
          }));
          setOpenManoObra(false);
          refreshTimeline();
        }}
      />

      <AgregarRepuestoModal
        open={openRepuesto}
        onClose={() => setOpenRepuesto(false)}
        ordenId={orden.id}
        onCreated={(item) => {
          setOrden((prev: any) => ({
            ...prev,
            repuestos: [item, ...(prev?.repuestos || [])],
          }));
          setOpenRepuesto(false);
          refreshTimeline();
        }}
      />

      <EditarManoObraModal
        open={openEditarManoObra}
        onClose={() => {
          setOpenEditarManoObra(false);
          setEditingManoObra(null);
        }}
        ordenId={orden.id}
        item={editingManoObra}
        esCerrada={esCerrada}
        onSaved={(upd) => {
          setOrden((prev: any) => ({
            ...prev,
            manoObra: (prev?.manoObra || []).map((x: any) =>
              x.id === upd.id ? { ...x, ...upd } : x
            ),
          }));
          refreshTimeline();
        }}
      />
    </div>
  );
}
